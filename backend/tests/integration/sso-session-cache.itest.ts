/**
 * `sso-session-cache.ts` against a real PostgreSQL.
 *
 * The unit suite mocks `db.execute`, so it asserts the SHAPE of the SQL string
 * and nothing else — a column that does not exist reads as a pass. Every
 * statement in this file is executed by the real planner against the real
 * schema, so the SQL either runs or it does not.
 *
 * Two of the statements here were, until migration 024, unable to run at all:
 * `removeAsync` (the consume, hit on EVERY SAML login) and
 * `promoteSessionToCompleted` both write `sso_sessions.updated_at`.
 */

import { describe, it, expect, beforeAll, afterAll, inject } from 'vitest';
import {
  connectSut,
  createSsoConfig,
  createTeam,
  createUser,
  countSessions,
  readSession,
  uniqueEmail,
  sql,
  type Sut,
} from './support/harness.js';

const pgFresh = inject('pgFresh');
const pgSkipReason = inject('pgSkipReason');

let n = 0;
const nextRequestId = () => `_req-cache-${process.pid}-${Date.now()}-${n++}`;

describe.skipIf(!pgFresh)(
  `SsoSessionCacheProvider against real PostgreSQL${pgSkipReason ? ` — SKIPPED: ${pgSkipReason}` : ''}`,
  () => {
    let sut: Sut;
    let configId: string;
    let otherConfigId: string;
    let teamId: string;

    beforeAll(async () => {
      sut = await connectSut(pgFresh as string);
      teamId = await createTeam(sut, 'session-cache-team');
      configId = await createSsoConfig(sut, teamId);
      otherConfigId = await createSsoConfig(sut, await createTeam(sut, 'other-team'));
    });

    afterAll(async () => {
      await sut?.close();
    });

    // ------------------------------------------------------------------
    // saveAsync — the INSERT
    // ------------------------------------------------------------------

    it('saveAsync writes the pending row with relay state, IP and user agent', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {
        relayState: '/dashboard',
        ipAddress: '203.0.113.9',
        userAgent: 'integration-agent',
      });

      const item = await provider.saveAsync(requestId, new Date().toISOString());
      expect(item).not.toBeNull();
      // node-saml compares `createdAt` against requestIdExpirationPeriodMs, so a
      // NaN here would silently reject every login.
      expect(Number.isFinite(item!.createdAt)).toBe(true);

      const rows = await sut.db.execute(
        sql`SELECT id, status, relay_state, host(ip_address) AS ip, user_agent
            FROM sso_sessions WHERE sso_config_id = ${configId} AND request_id = ${requestId}`
      );
      expect(rows.rows).toHaveLength(1);
      const row = rows.rows[0] as Record<string, unknown>;
      expect(row.status).toBe('pending');
      expect(row.relay_state).toBe('/dashboard');
      // `::inet` — a real cast against a real column type, which the mock cannot check.
      expect(row.ip).toBe('203.0.113.9');
      expect(row.user_agent).toBe('integration-agent');
    });

    it('saveAsync accepts a null IP address (the ::inet cast must tolerate NULL)', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      expect(await provider.saveAsync(requestId, 'ignored')).not.toBeNull();
      expect(await countSessions(sut, configId, requestId)).toBe(1);
    });

    // ------------------------------------------------------------------
    // uq_sso_sessions_pending_request — the partial unique index
    // ------------------------------------------------------------------

    it('the partial unique index prevents two PENDING rows for one (config, request_id)', async () => {
      const requestId = nextRequestId();
      const first = new sut.cache.SsoSessionCacheProvider(configId, {});
      const second = new sut.cache.SsoSessionCacheProvider(configId, {});

      expect(await first.saveAsync(requestId, 'x')).not.toBeNull();
      // ON CONFLICT DO NOTHING returns no row — but ONLY because the index
      // exists. Without `uq_sso_sessions_pending_request` this INSERT succeeds
      // and the single-use gate has two rows to consume.
      expect(await second.saveAsync(requestId, 'x')).toBeNull();
      expect(await countSessions(sut, configId, requestId)).toBe(1);
    });

    it('the index is PARTIAL: the same request_id may be re-used once the row is no longer pending', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      await provider.removeAsync(requestId); // -> 'failed'

      const again = new sut.cache.SsoSessionCacheProvider(configId, {});
      expect(await again.saveAsync(requestId, 'x')).not.toBeNull();
      expect(await countSessions(sut, configId, requestId)).toBe(2);
      expect(await countSessions(sut, configId, requestId, 'pending')).toBe(1);
    });

    it('the index is per-configuration: two tenants may hold the same request_id', async () => {
      const requestId = nextRequestId();
      expect(
        await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x')
      ).not.toBeNull();
      expect(
        await new sut.cache.SsoSessionCacheProvider(otherConfigId, {}).saveAsync(requestId, 'x')
      ).not.toBeNull();
    });

    // ------------------------------------------------------------------
    // getAsync — the read-only probe
    // ------------------------------------------------------------------

    it('getAsync returns a parseable ISO instant for a pending row', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');

      const value = await provider.getAsync(requestId);
      expect(value).not.toBeNull();
      // node-saml does `new Date(result)` and compares — a status token here
      // yields NaN and rejects every otherwise-valid login.
      expect(Number.isNaN(new Date(value as string).getTime())).toBe(false);
    });

    it('getAsync is tenant-scoped: another configuration cannot see the row', async () => {
      const requestId = nextRequestId();
      await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x');
      const foreign = new sut.cache.SsoSessionCacheProvider(otherConfigId, {});
      expect(await foreign.getAsync(requestId)).toBeNull();
    });

    it('getAsync does not mutate — it runs before signature verification', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      await provider.getAsync(requestId);
      expect(await countSessions(sut, configId, requestId, 'pending')).toBe(1);
    });

    // ------------------------------------------------------------------
    // removeAsync — the atomic single-use gate, and THE updated_at write
    // ------------------------------------------------------------------

    it("removeAsync consumes the row: status becomes 'failed' and updated_at is written", async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {
        relayState: '/after-login',
      });
      const saved = await provider.saveAsync(requestId, 'x');
      expect(saved).not.toBeNull();

      // A visible gap so an `updated_at` that was merely defaulted at INSERT
      // time is distinguishable from one this statement actually wrote.
      await new Promise((r) => setTimeout(r, 25));

      expect(await provider.removeAsync(requestId)).toBe(requestId);
      expect(provider.consumedSessionId).not.toBeNull();
      expect(provider.consumedRequestId).toBe(requestId);
      expect(provider.consumedRelayState).toBe('/after-login');

      const row = await readSession(sut, provider.consumedSessionId as string);
      // NOT 'completed': node-saml calls removeAsync from a terminal catch on
      // every failure path, so an unauthenticated attacker reaches it.
      expect(row.status).toBe('failed');
      expect(new Date(row.updated_at).getTime()).toBeGreaterThan(
        new Date(row.created_at).getTime()
      );
    });

    it('removeAsync is single-use: a second call consumes nothing', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');

      expect(await provider.removeAsync(requestId)).toBe(requestId);
      const replay = new sut.cache.SsoSessionCacheProvider(configId, {});
      expect(await replay.removeAsync(requestId)).toBeNull();
      expect(replay.consumedSessionId).toBeNull();
    });

    it('removeAsync is tenant-scoped: another configuration cannot consume the row', async () => {
      const requestId = nextRequestId();
      await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x');
      const foreign = new sut.cache.SsoSessionCacheProvider(otherConfigId, {});
      expect(await foreign.removeAsync(requestId)).toBeNull();
      expect(await countSessions(sut, configId, requestId, 'pending')).toBe(1);
    });

    it('removeAsync ignores a null or empty key without touching the table', async () => {
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      expect(await provider.removeAsync(null)).toBeNull();
      expect(await provider.removeAsync('')).toBeNull();
    });

    it('concurrent removeAsync calls: exactly one wins (READ COMMITTED / EvalPlanQual)', async () => {
      const requestId = nextRequestId();
      await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(requestId, 'x');

      // The single-use guarantee is a property of the DATABASE re-evaluating
      // `status = 'pending'` on a concurrently updated row. No mock can show it.
      const racers = Array.from({ length: 8 }, () =>
        new sut.cache.SsoSessionCacheProvider(configId, {})
      );
      const outcomes = await Promise.all(racers.map((p) => p.removeAsync(requestId)));
      expect(outcomes.filter((o) => o === requestId)).toHaveLength(1);
      expect(racers.filter((p) => p.consumedSessionId !== null)).toHaveLength(1);
    });

    // ------------------------------------------------------------------
    // promoteSessionToCompleted — the other updated_at write
    // ------------------------------------------------------------------

    it('promoteSessionToCompleted sets status, user_id, completed_at and updated_at', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      await provider.removeAsync(requestId);
      const sessionId = provider.consumedSessionId as string;

      const userId = await createUser(sut, uniqueEmail('promote'));
      const consumed = await readSession(sut, sessionId);
      await new Promise((r) => setTimeout(r, 25));

      expect(await sut.cache.promoteSessionToCompleted(sessionId, userId)).toBe(true);

      const row = await readSession(sut, sessionId);
      expect(row.status).toBe('completed');
      expect(row.user_id).toBe(userId);
      expect(row.completed_at).not.toBeNull();
      expect(new Date(row.updated_at).getTime()).toBeGreaterThan(
        new Date(consumed.updated_at).getTime()
      );
    });

    it('promoteSessionToCompleted only promotes a row still in the neutral failed state', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      await provider.removeAsync(requestId);
      const sessionId = provider.consumedSessionId as string;
      const userId = await createUser(sut, uniqueEmail('promote-twice'));

      expect(await sut.cache.promoteSessionToCompleted(sessionId, userId)).toBe(true);
      // Second promotion matches zero rows — the caller logs an audit-integrity
      // warning rather than failing an already-authenticated login.
      expect(await sut.cache.promoteSessionToCompleted(sessionId, userId)).toBe(false);
    });

    it('promoteSessionToCompleted refuses a row that was never consumed', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      const pending = await sut.db.execute(
        sql`SELECT id FROM sso_sessions WHERE sso_config_id = ${configId} AND request_id = ${requestId}`
      );
      const userId = await createUser(sut, uniqueEmail('never-consumed'));
      expect(
        await sut.cache.promoteSessionToCompleted(
          (pending.rows[0] as { id: string }).id,
          userId
        )
      ).toBe(false);
    });

    // ------------------------------------------------------------------
    // cleanupExpiredSessions
    // ------------------------------------------------------------------

    it('cleanupExpiredSessions expires only pending rows older than the window', async () => {
      const stale = nextRequestId();
      const live = nextRequestId();
      await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(stale, 'x');
      await new sut.cache.SsoSessionCacheProvider(configId, {}).saveAsync(live, 'x');
      await sut.db.execute(
        sql`UPDATE sso_sessions SET created_at = NOW() - INTERVAL '11 minutes'
            WHERE sso_config_id = ${configId} AND request_id = ${stale}`
      );

      expect(await sut.service.cleanupExpiredSessions()).toBeGreaterThanOrEqual(1);
      expect(await countSessions(sut, configId, stale, 'expired')).toBe(1);
      expect(await countSessions(sut, configId, live, 'pending')).toBe(1);
    });

    it('a session older than the 10-minute window can no longer be read or consumed', async () => {
      const requestId = nextRequestId();
      const provider = new sut.cache.SsoSessionCacheProvider(configId, {});
      await provider.saveAsync(requestId, 'x');
      await sut.db.execute(
        sql`UPDATE sso_sessions SET created_at = NOW() - INTERVAL '11 minutes'
            WHERE sso_config_id = ${configId} AND request_id = ${requestId}`
      );

      expect(await provider.getAsync(requestId)).toBeNull();
      expect(await provider.removeAsync(requestId)).toBeNull();
    });
  }
);
