/**
 * Assertion-ID single-use store (REQ-008).
 *
 * The session gate (`sso_sessions`) and this gate are independent on purpose: a
 * replayed assertion carrying a FRESH `InResponseTo` passes the session gate,
 * and only this one stops it.
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('saml-assertion-replay');

/** Opportunistic cleanup runs at most once per this interval. */
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

let lastCleanupAt = 0;

interface ReplayIdRow {
  id: string;
}

/**
 * Claim an assertion ID for this configuration.
 *
 * @returns true if the ID had not been seen before; false means REPLAY. Zero
 *          rows returned by the INSERT is the whole signal — the unique
 *          constraint does the work, so there is no read-then-write window.
 */
export async function claimAssertionId(
  ssoConfigId: string,
  assertionId: string,
  expiresAt: Date
): Promise<boolean> {
  const result = await db.execute(
    sql`INSERT INTO saml_assertion_replay (sso_config_id, assertion_id, expires_at)
        VALUES (${ssoConfigId}, ${assertionId}, ${expiresAt.toISOString()})
        ON CONFLICT (sso_config_id, assertion_id) DO NOTHING
        RETURNING id`
  );

  return result.rows.length > 0 && (result.rows[0] as unknown as ReplayIdRow) != null;
}

/**
 * Delete replay records that can no longer protect anything. A row is needed
 * only while its assertion could still be replayed successfully, which
 * `expires_at` already encodes.
 *
 * Mirrors the existing exported `cleanupExpiredSessions()`.
 */
export async function cleanupExpiredAssertionIds(): Promise<number> {
  const result = await db.execute(
    sql`DELETE FROM saml_assertion_replay WHERE expires_at < NOW()`
  );
  return result.rowCount || 0;
}

/**
 * Best-effort, rate-limited cleanup triggered from the ACS path so the table
 * cannot grow without bound in a deployment that never wires up a cron.
 *
 * Never blocks and never fails the request: a cleanup problem is a maintenance
 * concern, not an authentication one.
 */
export async function maybeCleanupExpiredAssertionIds(): Promise<void> {
  const now = Date.now();
  if (now - lastCleanupAt < CLEANUP_INTERVAL_MS) return;
  lastCleanupAt = now;

  try {
    const deleted = await cleanupExpiredAssertionIds();
    if (deleted > 0) logger.debug({ deleted }, 'Expired SAML assertion replay records removed');
  } catch {
    // Bare catch, no binding: nothing from this path may reach a log line.
    logger.debug('SAML assertion replay cleanup skipped');
  }
}
