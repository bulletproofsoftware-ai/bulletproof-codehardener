/**
 * node-saml `CacheProvider` backed by `sso_sessions`, bound to one
 * `sso_config_id` so every statement is tenant-scoped.
 *
 * Design decision (§B.8.1): we implement the interface so node-saml gets the
 * READ semantics it needs for its `SubjectConfirmationData/@InResponseTo` <->
 * `Response/@InResponseTo` cross-check — a real check, inside the signature,
 * that we would otherwise have to re-implement by hand. But we do NOT delegate
 * the single-use guarantee to it:
 *
 *   1. node-saml never inspects `removeAsync`'s return value (all four call
 *      sites — `saml.js:628`, `:803`, `:814`, `:828` — are bare `await`
 *      expression statements), so two concurrent replays can both pass
 *      `getAsync` before either calls `removeAsync`. That is a TOCTOU race.
 *   2. There is a reachable path where `removeAsync` is not called at all
 *      (`SubjectConfirmationData` present but carrying no `InResponseTo`).
 *
 * So `removeAsync` here is a single atomic statement — read-then-write is
 * forbidden — and `processSAMLResponse` calls it unconditionally.
 */

import type { CacheItem, CacheProvider } from '@node-saml/node-saml';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';

/** Metadata `sso_sessions` records for the SP-initiated flow. */
export interface SsoRequestMeta {
  relayState?: string;
  ipAddress?: string;
  userAgent?: string;
}

interface SessionIdRow {
  id: string;
}

interface SessionCreatedRow {
  id: string;
  created_at: Date | string;
}

interface SessionCreatedAtRow {
  created_at: Date | string;
}

function toIsoString(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

export class SsoSessionCacheProvider implements CacheProvider {
  /** Set by `removeAsync` to the id of the row it consumed; null if it consumed nothing. */
  public consumedSessionId: string | null = null;

  /**
   * The `request_id` the consumed row carried. §B.8.5 compares the assertion's
   * `SubjectConfirmationData/@InResponseTo` against the request id ACTUALLY
   * consumed, not against the attacker-mutable `Response/@InResponseTo`.
   */
  public consumedRequestId: string | null = null;

  /**
   * @param ssoConfigId tenant scope for EVERY statement in this class.
   * @param requestMeta supplied only on the `initiateSAMLLogin` path, where
   *                    `saveAsync` runs. The ACS path never calls `saveAsync`.
   */
  constructor(
    private readonly ssoConfigId: string,
    private readonly requestMeta: SsoRequestMeta = {}
  ) {}

  /**
   * Create the pending session. Writes all three metadata columns so the
   * existing SSO audit trail survives the move behind this interface —
   * node-saml's two-string interface has no room for them, which is why they
   * travel on the constructor.
   *
   * node-saml's ISO instant is not stored: `getAsync` returns `created_at`,
   * which is the same instant maintained by the database.
   */
  async saveAsync(key: string, value: string): Promise<CacheItem | null> {
    const result = await db.execute(
      sql`INSERT INTO sso_sessions (sso_config_id, request_id, relay_state, ip_address, user_agent)
          VALUES (${this.ssoConfigId}, ${key}, ${this.requestMeta.relayState || null},
                  ${this.requestMeta.ipAddress || null}::inet, ${this.requestMeta.userAgent || null})
          ON CONFLICT DO NOTHING
          RETURNING id, created_at`
    );

    if (result.rows.length === 0) return null;
    const row = result.rows[0] as unknown as SessionCreatedRow;
    return { value, createdAt: new Date(toIsoString(row.created_at)).getTime() };
  }

  /**
   * READ-ONLY probe. Runs before signature verification, so it must never
   * mutate anything.
   *
   * MUST return an ISO instant: node-saml does `new Date(result)`
   * (`saml.js:810`) and then compares against `requestIdExpirationPeriodMs`, so
   * returning a status token like 'pending' yields NaN and a spurious
   * rejection.
   */
  async getAsync(key: string): Promise<string | null> {
    const result = await db.execute(
      sql`SELECT created_at FROM sso_sessions
          WHERE request_id = ${key} AND sso_config_id = ${this.ssoConfigId}
            AND status = 'pending'
            AND created_at > NOW() - INTERVAL '10 minutes'`
    );

    if (result.rows.length === 0) return null;
    return toIsoString((result.rows[0] as unknown as SessionCreatedAtRow).created_at);
  }

  /**
   * THE atomic single-use gate. One statement; read-then-write is forbidden.
   * Under Postgres READ COMMITTED the `WHERE status = 'pending'` predicate is
   * re-evaluated on a concurrently updated row (EvalPlanQual), so a second
   * concurrent POST matches zero rows.
   *
   * The terminal state is 'failed', NOT 'completed'. node-saml calls this from
   * a terminal `catch` wrapping the whole of `validatePostResponseAsync`
   * (`saml.js:625-631`), so it fires on EVERY failure path before any of our
   * code runs — meaning an unauthenticated attacker can reach it. Landing in
   * 'completed' would write a success record, with `user_id` NULL, into the
   * table that is the SSO evidence source. 'completed' must keep meaning "a
   * user actually logged in"; it is set only by `promoteSessionToCompleted`
   * after every check has passed.
   */
  async removeAsync(key: string | null): Promise<string | null> {
    if (key === null || key === '') return null;

    const result = await db.execute(
      sql`UPDATE sso_sessions
          SET status = 'failed', updated_at = NOW()
          WHERE request_id = ${key} AND sso_config_id = ${this.ssoConfigId}
            AND status = 'pending'
            AND created_at > NOW() - INTERVAL '10 minutes'
          RETURNING id`
    );

    if (result.rows.length === 0) return null;

    this.consumedSessionId = (result.rows[0] as unknown as SessionIdRow).id;
    this.consumedRequestId = key;
    return key;
  }
}

/**
 * Promote a consumed session to 'completed'. The last DB write of a successful
 * ACS flow, gated on the row still being in the neutral 'failed' state that
 * `removeAsync` left it in — so single-use atomicity is unaffected.
 */
export async function promoteSessionToCompleted(
  sessionId: string,
  userId: string
): Promise<void> {
  await db.execute(
    sql`UPDATE sso_sessions
        SET status = 'completed', user_id = ${userId}, completed_at = NOW(), updated_at = NOW()
        WHERE id = ${sessionId} AND status = 'failed'
        RETURNING id`
  );
}
