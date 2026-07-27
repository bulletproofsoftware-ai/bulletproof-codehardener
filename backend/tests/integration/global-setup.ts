/**
 * Vitest globalSetup for the PostgreSQL-backed integration suite.
 *
 * WHY THIS EXISTS
 * ---------------
 * The unit suite mocks `db/client.js`, so the mock *is* the database: SQL that
 * names a column which does not exist still "passes". That is exactly how
 * `sso_sessions.updated_at` shipped missing while 641 unit tests were green —
 * `sso-session-cache.ts` writes `updated_at` in `removeAsync` (hit on EVERY SAML
 * login) and again when promoting a session to 'completed'. Against a real
 * database the first SSO login would have thrown.
 *
 * So this harness stands up a THROWAWAY PostgreSQL, applies the real schema and
 * every migration in `postgres/migrations/`, and hands the tests a connection
 * string. Nothing here ever touches an operator's running database: the
 * container is created by this process, given a random port, and destroyed at
 * teardown.
 *
 * TWO DATABASES ARE BUILT, and the second is not redundant:
 *
 *   fresh   init.sql (= schema state through migration 018) + every migration in
 *           order. On this path `sso_sessions` is CREATEd by 019, which already
 *           declares `updated_at`, so 024's `ADD COLUMN updated_at` is a no-op.
 *
 *   legacy  init.sql + `postgres/011-sso-saml.sql` + every migration in order.
 *           011-sso-saml.sql creates `sso_sessions` WITHOUT `updated_at`, so
 *           019's `CREATE TABLE IF NOT EXISTS` is skipped and 024's ADD COLUMN
 *           is the ONLY thing that supplies the column. This reproduces the
 *           deployed topology in which the bug actually surfaced, and it is the
 *           configuration in which reverting 024 turns the suite red.
 *
 * SKIPPING: if Docker is unavailable the suite skips LOUDLY — a banner naming
 * the reason, and every describe block reported as skipped. Set
 * INTEGRATION_DB_REQUIRED=1 (CI, once a database service exists) to make an
 * unavailable Docker a hard failure instead.
 */

import { readdirSync } from 'node:fs';
import path from 'node:path';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import type { TestProject } from 'vitest/node';

const IMAGE = process.env.INTEGRATION_PG_IMAGE ?? 'postgres:16-alpine';
const DB_USER = 'ch_itest';
const DB_PASSWORD = 'ch_itest_pw';
const FRESH_DB = 'ch_itest_fresh';
const LEGACY_DB = 'ch_itest_legacy';

/** Where the repository's `postgres/` directory is mounted inside the container. */
const SQL_DIR = '/sql';

/** Outcome of one `psql -v ON_ERROR_STOP=1 -f <file>` invocation. */
export interface SqlFileResult {
  name: string;
  ok: boolean;
  /** psql output, trimmed. Empty on success (`-q`). */
  output: string;
}

export interface MigrationReport {
  /** Every file in postgres/migrations, in the same order `init-all.sh` applies them. */
  fresh: SqlFileResult[];
  legacy: SqlFileResult[];
}

let container: StartedPostgreSqlContainer | undefined;

/** Migration filenames in the order the shell glob in `scripts/init-all.sh` yields. */
function migrationFiles(migrationsDir: string): string[] {
  return readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
}

async function runSqlFile(
  c: StartedPostgreSqlContainer,
  database: string,
  containerPath: string,
  name: string
): Promise<SqlFileResult> {
  const result = await c.exec([
    'psql',
    '-v',
    'ON_ERROR_STOP=1',
    '-q',
    '-U',
    DB_USER,
    '-d',
    database,
    '-f',
    containerPath,
  ]);
  return { name, ok: result.exitCode === 0, output: result.output.trim() };
}

/**
 * Apply every migration in order, tolerating failures — the same contract as
 * `scripts/init-all.sh`, which deliberately does not abort: migrations 002-018
 * are already folded into init.sql and several are non-idempotent by
 * construction (015 renames a column, 017 adds a constraint with no IF NOT
 * EXISTS), so they legitimately fail when replayed over init.sql.
 *
 * Callers get the full per-file result and decide what counts as a failure.
 * `migrations.itest.ts` asserts that every migration NOT superseded by init.sql
 * applied cleanly.
 */
async function applyMigrations(
  c: StartedPostgreSqlContainer,
  database: string,
  migrationsDir: string
): Promise<SqlFileResult[]> {
  const results: SqlFileResult[] = [];
  for (const name of migrationFiles(migrationsDir)) {
    results.push(await runSqlFile(c, database, `${SQL_DIR}/migrations/${name}`, name));
  }
  return results;
}

function connectionUri(c: StartedPostgreSqlContainer, database: string): string {
  return `postgres://${DB_USER}:${DB_PASSWORD}@${c.getHost()}:${c.getMappedPort(5432)}/${database}`;
}

function banner(lines: string[]): void {
  const bar = '='.repeat(78);
  process.stderr.write(`\n${bar}\n${lines.join('\n')}\n${bar}\n\n`);
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const { provide } = project;
  // `project.config.root` is `backend/` (where vitest.integration.config.ts
  // lives), so the repository root is one level up. Derived rather than
  // hard-coded relative to this file so the paths stay correct wherever vitest
  // is invoked from.
  const repoRoot = path.resolve(project.config.root, '..');
  const postgresDir = path.join(repoRoot, 'postgres');
  const migrationsDir = path.join(postgresDir, 'migrations');

  try {
    container = await new PostgreSqlContainer(IMAGE)
      // The container owns a database named after the harness, never
      // `codehardener` — a throwaway that cannot be confused with a real one.
      .withDatabase(FRESH_DB)
      .withUsername(DB_USER)
      .withPassword(DB_PASSWORD)
      .withCopyDirectoriesToContainer([{ source: postgresDir, target: SQL_DIR }])
      .start();
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : 'unknown error starting the PostgreSQL container';
    if (process.env.INTEGRATION_DB_REQUIRED === '1') {
      throw new Error(
        `INTEGRATION_DB_REQUIRED=1 but no PostgreSQL could be started: ${reason}`
      );
    }
    banner([
      'SKIPPED: PostgreSQL integration tests did NOT run.',
      '',
      `Reason: ${reason}`,
      '',
      'These tests are the only coverage of SQL the in-memory unit mock cannot',
      'validate (a nonexistent column still "passes" against the mock). A green',
      'unit run does NOT mean the SSO SQL executes.',
      '',
      'To run them: start Docker, then `npm run test:db` from backend/.',
      'To make an unavailable database a hard failure: INTEGRATION_DB_REQUIRED=1.',
    ]);
    provide('pgFresh', null);
    provide('pgLegacy', null);
    provide('pgSkipReason', reason);
    provide('migrationReport', null);
    return async () => {
      /* nothing was started */
    };
  }

  const c = container;

  // --- fresh path: init.sql (schema through 018) + every migration ----------
  const freshInit = await runSqlFile(c, FRESH_DB, `${SQL_DIR}/init.sql`, 'init.sql');
  if (!freshInit.ok) {
    throw new Error(`postgres/init.sql failed to apply:\n${freshInit.output}`);
  }
  const fresh = await applyMigrations(c, FRESH_DB, migrationsDir);

  // --- legacy path: init.sql + the pre-migrations SSO schema + every migration
  const createLegacy = await c.exec([
    'psql',
    '-v',
    'ON_ERROR_STOP=1',
    '-q',
    '-U',
    DB_USER,
    '-d',
    'postgres',
    '-c',
    `CREATE DATABASE ${LEGACY_DB}`,
  ]);
  if (createLegacy.exitCode !== 0) {
    throw new Error(`could not create ${LEGACY_DB}:\n${createLegacy.output}`);
  }
  const legacyInit = await runSqlFile(c, LEGACY_DB, `${SQL_DIR}/init.sql`, 'init.sql');
  if (!legacyInit.ok) {
    throw new Error(`postgres/init.sql failed to apply to ${LEGACY_DB}:\n${legacyInit.output}`);
  }
  const legacySso = await runSqlFile(
    c,
    LEGACY_DB,
    `${SQL_DIR}/011-sso-saml.sql`,
    '011-sso-saml.sql'
  );
  if (!legacySso.ok) {
    throw new Error(`postgres/011-sso-saml.sql failed to apply:\n${legacySso.output}`);
  }
  const legacy = await applyMigrations(c, LEGACY_DB, migrationsDir);

  provide('pgFresh', connectionUri(c, FRESH_DB));
  provide('pgLegacy', connectionUri(c, LEGACY_DB));
  provide('pgSkipReason', null);
  provide('migrationReport', { fresh, legacy } satisfies MigrationReport);

  return async () => {
    await c.stop();
    container = undefined;
  };
}

declare module 'vitest' {
  export interface ProvidedContext {
    pgFresh: string | null;
    pgLegacy: string | null;
    pgSkipReason: string | null;
    migrationReport: MigrationReport | null;
  }
}
