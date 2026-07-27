/**
 * `assertion-replay.ts` against a real PostgreSQL.
 *
 * The whole control is a database constraint. `claimAssertionId` does an
 * `INSERT ... ON CONFLICT (sso_config_id, assertion_id) DO NOTHING RETURNING id`
 * and reads "zero rows" as REPLAY — there is deliberately no read-then-write
 * window in the application. That means the unit suite cannot test the control
 * at all: with `db.execute` mocked, the rejection is whatever the mock was told
 * to return. Only a real unique constraint can reject a replay, so only these
 * tests exercise the gate as shipped.
 */

import { describe, it, expect, beforeAll, afterAll, inject } from 'vitest';
import {
  connectSut,
  createSsoConfig,
  createTeam,
  sql,
  type Sut,
} from './support/harness.js';

const pgFresh = inject('pgFresh');
const pgSkipReason = inject('pgSkipReason');

let n = 0;
const nextAssertionId = () => `_assert-${process.pid}-${Date.now()}-${n++}`;
const inFiveMinutes = () => new Date(Date.now() + 5 * 60_000);

describe.skipIf(!pgFresh)(
  `SAML assertion replay store against real PostgreSQL${pgSkipReason ? ` — SKIPPED: ${pgSkipReason}` : ''}`,
  () => {
    let sut: Sut;
    let configId: string;
    let otherConfigId: string;

    beforeAll(async () => {
      sut = await connectSut(pgFresh as string);
      configId = await createSsoConfig(sut, await createTeam(sut, 'replay-team'));
      otherConfigId = await createSsoConfig(sut, await createTeam(sut, 'replay-team-other'));
    });

    afterAll(async () => {
      await sut?.close();
    });

    it('claims an unseen assertion ID and persists the row', async () => {
      const assertionId = nextAssertionId();
      const expiresAt = inFiveMinutes();

      expect(await sut.replay.claimAssertionId(configId, assertionId, expiresAt)).toBe(true);

      const rows = await sut.db.execute(
        sql`SELECT sso_config_id, assertion_id, seen_at, expires_at
            FROM saml_assertion_replay
            WHERE sso_config_id = ${configId} AND assertion_id = ${assertionId}`
      );
      expect(rows.rows).toHaveLength(1);
      const row = rows.rows[0] as Record<string, unknown>;
      expect(row.assertion_id).toBe(assertionId);
      expect(row.seen_at).not.toBeNull();
      expect(new Date(row.expires_at as string).getTime()).toBeCloseTo(expiresAt.getTime(), -3);
    });

    it('REJECTS a replayed assertion ID — the unique constraint does the work', async () => {
      const assertionId = nextAssertionId();
      expect(await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())).toBe(true);
      // Second claim: the DB's uq_saml_assertion_replay makes the INSERT a
      // no-op, so RETURNING yields zero rows.
      expect(await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())).toBe(false);
      // And it stayed a single row — no duplicate slipped in.
      const rows = await sut.db.execute(
        sql`SELECT COUNT(*)::int AS n FROM saml_assertion_replay
            WHERE sso_config_id = ${configId} AND assertion_id = ${assertionId}`
      );
      expect((rows.rows[0] as { n: number }).n).toBe(1);
    });

    it('rejects a replay even when the second claim carries a later expiry', async () => {
      const assertionId = nextAssertionId();
      await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes());
      const far = new Date(Date.now() + 24 * 3600_000);
      expect(await sut.replay.claimAssertionId(configId, assertionId, far)).toBe(false);
      // DO NOTHING, not DO UPDATE: the original expiry must survive, otherwise a
      // replay could extend its own retention window.
      const rows = await sut.db.execute(
        sql`SELECT expires_at FROM saml_assertion_replay
            WHERE sso_config_id = ${configId} AND assertion_id = ${assertionId}`
      );
      expect(new Date((rows.rows[0] as { expires_at: string }).expires_at).getTime()).toBeLessThan(
        far.getTime()
      );
    });

    it('is scoped per configuration: the same assertion ID is claimable by another tenant', async () => {
      const assertionId = nextAssertionId();
      expect(await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())).toBe(true);
      expect(await sut.replay.claimAssertionId(otherConfigId, assertionId, inFiveMinutes())).toBe(
        true
      );
    });

    it('survives concurrent claims of the same ID: exactly one wins', async () => {
      const assertionId = nextAssertionId();
      const results = await Promise.all(
        Array.from({ length: 8 }, () =>
          sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())
        )
      );
      expect(results.filter(Boolean)).toHaveLength(1);
    });

    it('retention delete removes expired rows and leaves live ones', async () => {
      const expired = nextAssertionId();
      const live = nextAssertionId();
      await sut.replay.claimAssertionId(configId, expired, new Date(Date.now() - 60_000));
      await sut.replay.claimAssertionId(configId, live, inFiveMinutes());

      const deleted = await sut.replay.cleanupExpiredAssertionIds();
      expect(deleted).toBeGreaterThanOrEqual(1);

      const remaining = await sut.db.execute(
        sql`SELECT assertion_id FROM saml_assertion_replay
            WHERE sso_config_id = ${configId} AND assertion_id IN (${expired}, ${live})`
      );
      expect(remaining.rows.map((r) => (r as { assertion_id: string }).assertion_id)).toEqual([
        live,
      ]);
    });

    it('an expired ID becomes claimable again once retention has swept it', async () => {
      const assertionId = nextAssertionId();
      await sut.replay.claimAssertionId(configId, assertionId, new Date(Date.now() - 60_000));
      expect(await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())).toBe(false);
      await sut.replay.cleanupExpiredAssertionIds();
      // Correct by design: a row past expires_at can no longer protect anything,
      // because the assertion it names is itself past NotOnOrAfter.
      expect(await sut.replay.claimAssertionId(configId, assertionId, inFiveMinutes())).toBe(true);
    });

    it('the opportunistic cleanup runs against the real schema without throwing', async () => {
      // It swallows every error by design, so a broken DELETE would be invisible
      // in production. Executing the same statement directly is what proves it.
      await expect(sut.replay.maybeCleanupExpiredAssertionIds()).resolves.toBeUndefined();
      await expect(sut.replay.cleanupExpiredAssertionIds()).resolves.toBeTypeOf('number');
    });

    it('deletes replay rows when the configuration is deleted (ON DELETE CASCADE)', async () => {
      const doomedConfig = await createSsoConfig(sut, await createTeam(sut, 'replay-team-doomed'));
      const assertionId = nextAssertionId();
      await sut.replay.claimAssertionId(doomedConfig, assertionId, inFiveMinutes());

      await sut.db.execute(sql`DELETE FROM sso_configurations WHERE id = ${doomedConfig}`);

      const rows = await sut.db.execute(
        sql`SELECT COUNT(*)::int AS n FROM saml_assertion_replay WHERE sso_config_id = ${doomedConfig}`
      );
      expect((rows.rows[0] as { n: number }).n).toBe(0);
    });
  }
);
