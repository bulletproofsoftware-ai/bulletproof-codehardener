/**
 * Every migration in `postgres/migrations/` is applied, in order, against a
 * fresh database — and then the schema is checked for the specific objects the
 * SSO code names in SQL.
 *
 * This is the gate that would have caught 024. `sso-session-cache.ts` writes
 * `sso_sessions.updated_at`; that column did not exist; 641 unit tests passed
 * anyway because the unit suite's database is an in-memory mock. A schema
 * assertion cannot be fooled that way.
 *
 * Two databases are checked, and the difference between them matters:
 *
 *   fresh   `sso_sessions` is created by migration 019, which already declares
 *           `updated_at`. On this path 024's `ADD COLUMN updated_at` is dead
 *           weight — reverting it changes nothing.
 *
 *   legacy  `sso_sessions` is created by `postgres/011-sso-saml.sql`, which has
 *           no `updated_at`, so 019's `CREATE TABLE IF NOT EXISTS` is skipped
 *           and 024's ADD COLUMN is the ONLY source of the column. This is the
 *           shape of the database the bug was found on, and the configuration
 *           in which reverting 024 turns this file red.
 */

import { describe, it, expect, beforeAll, afterAll, inject } from 'vitest';
import type { Client } from 'pg';
import { openRawClient } from './support/harness.js';

const pgFresh = inject('pgFresh');
const pgLegacy = inject('pgLegacy');
const pgSkipReason = inject('pgSkipReason');
const migrationReport = inject('migrationReport');

/**
 * Migrations 002-018 are already folded into `postgres/init.sql` (its header
 * says so, as does docs/architecture.md), and several are non-idempotent by
 * construction — 015 renames a column, 017 adds a constraint with no
 * IF NOT EXISTS — so replaying them over init.sql legitimately fails.
 * `scripts/init-all.sh` tolerates exactly this. Everything NUMBERED ABOVE 018
 * post-dates init.sql and must apply cleanly; that is the assertion below, and
 * it is what will catch the next 024.
 */
function isSupersededByInitSql(name: string): boolean {
  const n = Number(name.slice(0, 3));
  return Number.isFinite(n) && n <= 18;
}

/** Objects the SSO code names in SQL. Absence of any one of them is a runtime failure. */
const REQUIRED_COLUMNS: ReadonlyArray<readonly [table: string, column: string, why: string]> = [
  // sso-session-cache.ts saveAsync
  ['sso_sessions', 'sso_config_id', 'saveAsync INSERT / every tenant-scoped predicate'],
  ['sso_sessions', 'request_id', 'saveAsync INSERT, getAsync + removeAsync predicate'],
  ['sso_sessions', 'relay_state', 'saveAsync INSERT, removeAsync RETURNING'],
  ['sso_sessions', 'ip_address', 'saveAsync INSERT (::inet cast)'],
  ['sso_sessions', 'user_agent', 'saveAsync INSERT'],
  ['sso_sessions', 'created_at', 'saveAsync RETURNING, getAsync, 10-minute window'],
  ['sso_sessions', 'status', "removeAsync SET status='failed'"],
  // THE regression. Written by removeAsync (every SAML login) and by
  // promoteSessionToCompleted, and absent from the deployed schema until 024.
  ['sso_sessions', 'updated_at', 'removeAsync + promoteSessionToCompleted SET updated_at=NOW()'],
  ['sso_sessions', 'user_id', 'promoteSessionToCompleted SET user_id'],
  ['sso_sessions', 'completed_at', 'promoteSessionToCompleted SET completed_at=NOW()'],
  // assertion-replay.ts
  ['saml_assertion_replay', 'sso_config_id', 'claimAssertionId INSERT + conflict target'],
  ['saml_assertion_replay', 'assertion_id', 'claimAssertionId INSERT + conflict target'],
  ['saml_assertion_replay', 'expires_at', 'claimAssertionId INSERT, cleanup DELETE predicate'],
  // saml.service.ts resolveSSOUser
  ['users', 'sso_provider', 'resolveSSOUser SELECT + provisioning INSERT'],
  ['users', 'sso_subject_id', 'resolveSSOUser SELECT + provisioning INSERT'],
  // saml.service.ts getSSOConfig / upsertSSOConfig
  ['sso_configurations', 'attribute_mapping', 'getSSOConfig SELECT, upsert INSERT ::jsonb'],
  ['sso_configurations', 'auto_add_to_team', 'getSSOConfig SELECT'],
  ['sso_configurations', 'allow_unencrypted_assertion', 'getSSOConfig SELECT'],
  ['sso_configurations', 'updated_at', 'upsertSSOConfig + toggleSSO SET updated_at=NOW()'],
];

/** Index / constraint names the security controls depend on. */
const REQUIRED_INDEXES: ReadonlyArray<readonly [name: string, why: string]> = [
  [
    'uq_sso_sessions_pending_request',
    'partial unique index — at most one PENDING row per (config, request_id)',
  ],
  ['uq_saml_assertion_replay', 'unique (sso_config_id, assertion_id) — the replay gate'],
];

async function columnExists(c: Client, table: string, column: string): Promise<boolean> {
  const r = await c.query(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
    [table, column]
  );
  return r.rowCount === 1;
}

async function relationExists(c: Client, name: string): Promise<boolean> {
  const r = await c.query(
    `SELECT 1 FROM pg_class cl
       JOIN pg_namespace ns ON ns.oid = cl.relnamespace
      WHERE ns.nspname = 'public' AND cl.relname = $1`,
    [name]
  );
  return r.rowCount === 1;
}

describe.skipIf(!pgFresh)(
  `migrations against real PostgreSQL${pgSkipReason ? ` — SKIPPED: ${pgSkipReason}` : ''}`,
  () => {
    let fresh: Client;
    let legacy: Client;

    beforeAll(async () => {
      fresh = await openRawClient(pgFresh as string);
      legacy = await openRawClient(pgLegacy as string);
    });

    afterAll(async () => {
      await fresh?.end();
      await legacy?.end();
    });

    it('applies every migration that post-dates init.sql, on a fresh database', () => {
      const report = migrationReport;
      expect(report).not.toBeNull();
      const failures = report!.fresh
        .filter((m) => !isSupersededByInitSql(m.name) && !m.ok)
        .map((m) => `${m.name}: ${m.output}`);
      expect(failures).toEqual([]);
    });

    it('applies every migration that post-dates init.sql, on a legacy 011-sso-saml database', () => {
      const report = migrationReport;
      const failures = report!.legacy
        .filter((m) => !isSupersededByInitSql(m.name) && !m.ok)
        .map((m) => `${m.name}: ${m.output}`);
      expect(failures).toEqual([]);
    });

    it('actually ran the SSO migrations rather than finding none', () => {
      const names = migrationReport!.fresh.map((m) => m.name);
      expect(names).toContain('019_sso_gdpr_tables.sql');
      expect(names).toContain('024_saml_replay_protection.sql');
      // Applied in the same order scripts/init-all.sh applies them.
      expect(names.indexOf('019_sso_gdpr_tables.sql')).toBeLessThan(
        names.indexOf('024_saml_replay_protection.sql')
      );
    });

    describe.each([
      ['fresh (init.sql + migrations)', () => fresh],
      ['legacy (init.sql + 011-sso-saml.sql + migrations)', () => legacy],
    ])('%s', (_label, pick) => {
      it.each(REQUIRED_COLUMNS)('has %s.%s — %s', async (table, column) => {
        expect(await columnExists(pick(), table, column)).toBe(true);
      });

      it.each(REQUIRED_INDEXES)('has %s — %s', async (name) => {
        expect(await relationExists(pick(), name)).toBe(true);
      });

      it('has the saml_assertion_replay table', async () => {
        expect(await relationExists(pick(), 'saml_assertion_replay')).toBe(true);
      });

      it('admits every sso_sessions.status value the code writes', async () => {
        // Asserted by execution rather than by reading the constraint text: the
        // two migration paths disagree about whether a CHECK exists at all
        // (019 declares one, 011-sso-saml.sql does not), and what matters to the
        // running code is only that 'pending' -> 'failed' -> 'completed' are all
        // accepted. Rolled back, so no row survives this test.
        const c = pick();
        await c.query('BEGIN');
        try {
          const team = await c.query(`INSERT INTO teams (name) VALUES ('status-probe') RETURNING id`);
          const cfg = await c.query(
            `INSERT INTO sso_configurations
               (team_id, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, sp_acs_url)
             VALUES ($1, 'e', 'u', 'c', 'se', 'sa') RETURNING id`,
            [team.rows[0].id]
          );
          const session = await c.query(
            `INSERT INTO sso_sessions (sso_config_id, request_id) VALUES ($1, '_probe') RETURNING id, status`,
            [cfg.rows[0].id]
          );
          expect(session.rows[0].status).toBe('pending');
          for (const status of ['failed', 'completed', 'expired']) {
            const updated = await c.query(
              `UPDATE sso_sessions SET status = $1 WHERE id = $2 RETURNING status`,
              [status, session.rows[0].id]
            );
            expect(updated.rows[0].status).toBe(status);
          }
        } finally {
          await c.query('ROLLBACK');
        }
      });
    });

    it('leaves the legacy database with the same sso_sessions columns as the fresh one', async () => {
      // Two migration paths, one schema. If they diverge, one deployment shape
      // is running SQL the other never proved.
      const cols = async (c: Client) =>
        (
          await c.query(
            `SELECT column_name FROM information_schema.columns
              WHERE table_schema='public' AND table_name='sso_sessions'
              ORDER BY column_name`
          )
        ).rows.map((r: { column_name: string }) => r.column_name);

      const freshCols = await cols(fresh);
      const legacyCols = await cols(legacy);
      // `error_message` exists only on the legacy path (011-sso-saml.sql
      // declared it; 019 dropped it from the definition). Nothing reads it.
      expect(freshCols).toContain('updated_at');
      expect(legacyCols).toContain('updated_at');
      expect(freshCols.filter((c) => !legacyCols.includes(c))).toEqual([]);
    });
  }
);
