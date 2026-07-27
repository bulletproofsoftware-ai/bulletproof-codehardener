/**
 * The session-consume path against a LEGACY-schema database.
 *
 * This file exists for one reason: it is the only place where migration 024's
 * `ALTER TABLE sso_sessions ADD COLUMN IF NOT EXISTS updated_at` is load-bearing.
 *
 * On a database built the "fresh" way — `postgres/init.sql` then every migration
 * — `sso_sessions` is created by 019, whose CREATE TABLE already declares
 * `updated_at`, so 024's ADD COLUMN is a no-op and deleting it breaks nothing.
 *
 * The deployment where the bug actually surfaced was not built that way. Its
 * `sso_sessions` came from `postgres/011-sso-saml.sql`, which has no
 * `updated_at`; 019's `CREATE TABLE IF NOT EXISTS` therefore skipped the table
 * entirely, and 024's ADD COLUMN was the only statement that would have supplied
 * the column. That is the database this file runs against.
 *
 * Consequence, and the point of the exercise: revert the ADD COLUMN line in
 * `024_saml_replay_protection.sql` and these tests fail with
 * `column "updated_at" of relation "sso_sessions" does not exist` — the exact
 * error the operator hit — while the entire 641-test unit suite stays green.
 */

import { describe, it, expect, beforeAll, afterAll, inject } from 'vitest';
import {
  connectSut,
  createSsoConfig,
  createTeam,
  createUser,
  readSession,
  uniqueEmail,
  type Sut,
} from './support/harness.js';

const pgLegacy = inject('pgLegacy');
const pgSkipReason = inject('pgSkipReason');

let n = 0;
const nextRequestId = () => `_req-legacy-${process.pid}-${Date.now()}-${n++}`;

describe.skipIf(!pgLegacy)(
  `session consume on a legacy 011-sso-saml schema${pgSkipReason ? ` — SKIPPED: ${pgSkipReason}` : ''}`,
  () => {
    let sut: Sut;
    let configId: string;

    beforeAll(async () => {
      sut = await connectSut(pgLegacy as string);
      configId = await createSsoConfig(sut, await createTeam(sut, 'legacy-team'));
    });

    afterAll(async () => {
      await sut?.close();
    });

    it('removeAsync — the statement every SAML login executes — runs against the legacy table', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {
        relayState: '/legacy',
        ipAddress: '203.0.113.42',
        userAgent: 'legacy-agent',
      });
      expect(await provider.saveAsync(requestId, new Date().toISOString())).not.toBeNull();

      await new Promise((r) => setTimeout(r, 25));

      // `UPDATE sso_sessions SET status='failed', updated_at=NOW() ...`
      // Without migration 024 this throws: column "updated_at" does not exist.
      expect(await provider.removeAsync(requestId)).toBe(requestId);
      expect(provider.consumedRelayState).toBe('/legacy');

      const row = await readSession(sut, provider.consumedSessionId as string);
      expect(row.status).toBe('failed');
      expect(new Date(row.updated_at).getTime()).toBeGreaterThan(
        new Date(row.created_at).getTime()
      );
    });

    it('promoteSessionToCompleted — the last write of a successful login — runs against the legacy table', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, new Date().toISOString());
      await provider.removeAsync(requestId);
      const sessionId = provider.consumedSessionId as string;

      const consumed = await readSession(sut, sessionId);
      const userId = await createUser(sut, uniqueEmail('legacy'));
      await new Promise((r) => setTimeout(r, 25));

      // `UPDATE ... SET status='completed', user_id=..., completed_at=NOW(), updated_at=NOW()`
      expect(await sut.cache.promoteSessionToCompleted(sessionId, userId)).toBe(true);

      const row = await readSession(sut, sessionId);
      expect(row.status).toBe('completed');
      expect(row.user_id).toBe(userId);
      expect(new Date(row.updated_at).getTime()).toBeGreaterThan(
        new Date(consumed.updated_at).getTime()
      );
    });

    it('the partial unique index from 024 is present and enforced on the legacy table', async () => {
      const requestId = nextRequestId();
      expect(
        await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x')
      ).not.toBeNull();
      expect(
        await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x')
      ).toBeNull();
    });

    it('the assertion-replay gate from 024 rejects a replay on the legacy database', async () => {
      const assertionId = `_assert-legacy-${process.pid}-${Date.now()}`;
      const expiresAt = new Date(Date.now() + 5 * 60_000);
      expect(await sut.replay.claimAssertionId(configId, assertionId, expiresAt)).toBe(true);
      expect(await sut.replay.claimAssertionId(configId, assertionId, expiresAt)).toBe(false);
    });
  }
);
