/**
 * Shared plumbing for the PostgreSQL-backed integration tests.
 *
 * The modules under test read their connection string through
 * `src/config/env.ts`, which parses `process.env` at IMPORT time and is then
 * frozen for the life of the module registry. So the connection string must be
 * in `process.env` BEFORE `src/db/client.js` is first imported — which is why
 * every test file loads its subject through `connectSut()` inside `beforeAll`
 * and uses dynamic `import()`, never a top-level static import.
 */

import { sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';

export { sql };

/**
 * A plain `pg` connection, independent of the application's module registry.
 *
 * Schema assertions use this rather than `connectSut`: `src/db/client.ts` is a
 * module-level singleton, so a single test file cannot point it at two
 * databases, and `migrations.itest.ts` has to inspect both.
 */
export async function openRawClient(databaseUrl: string): Promise<Client> {
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  return client;
}

export type Sut = Awaited<ReturnType<typeof connectSut>>;

/**
 * Point the application's real database client at `databaseUrl` and load the
 * SSO modules against it.
 *
 * Nothing about the data path is mocked: real `pg`, real `drizzle-orm`, real
 * SQL, real schema. Only `utils/logger.js` is replaced, by the caller, and only
 * so the structured rejection `reason` — which `rejectSaml` sends to the log and
 * nowhere else — can be asserted.
 */
export async function connectSut(databaseUrl: string) {
  process.env.NODE_ENV = 'test';
  process.env.DATABASE_URL = databaseUrl;
  // The SSO kill-switch defaults to OFF in production; every SAML entry point
  // checks it first, so without this the whole suite would go green on
  // `sso_disabled` while proving nothing.
  process.env.SSO_ENABLED = 'true';
  process.env.JWT_SECRET = 'integration-test-only-secret';
  process.env.LOG_LEVEL = 'fatal';

  const [client, cache, replay, service, errors] = await Promise.all([
    import('../../../src/db/client.js'),
    import('../../../src/services/sso/sso-session-cache.js'),
    import('../../../src/services/sso/assertion-replay.js'),
    import('../../../src/services/sso/saml.service.js'),
    import('../../../src/middleware/errorHandler.js'),
  ]);

  return {
    db: client.db,
    cache,
    replay,
    service,
    errors,
    close: () => client.closeDbConnection(),
  };
}

// ============================================================================
// Fixtures. Every row is created with a fresh UUID / unique email so files that
// share the database cannot collide.
// ============================================================================

export function uniqueEmail(prefix = 'user'): string {
  return `${prefix}-${randomUUID()}@example.test`;
}

export async function createTeam(sut: Sut, name = 'Integration Team'): Promise<string> {
  const result = await sut.db.execute(
    sql`INSERT INTO teams (name) VALUES (${name}) RETURNING id`
  );
  return (result.rows[0] as { id: string }).id;
}

export interface SsoConfigOverrides {
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpCertificate?: string;
  spEntityId?: string;
  spAcsUrl?: string;
  attributeMapping?: Record<string, string>;
  enabled?: boolean;
  autoProvisionUsers?: boolean;
  autoAddToTeam?: boolean;
  defaultRole?: string;
}

/**
 * Insert a row straight into `sso_configurations`. Used where the test needs a
 * configuration to exist; the service's own `upsertSSOConfig` is exercised
 * separately, as a subject rather than as a fixture.
 */
export async function createSsoConfig(
  sut: Sut,
  teamId: string,
  o: SsoConfigOverrides = {}
): Promise<string> {
  const result = await sut.db.execute(
    sql`INSERT INTO sso_configurations (
          team_id, idp_entity_id, idp_sso_url, idp_certificate,
          sp_entity_id, sp_acs_url, attribute_mapping,
          enabled, auto_provision_users, auto_add_to_team, default_role
        ) VALUES (
          ${teamId},
          ${o.idpEntityId ?? 'https://idp.example.test/entity'},
          ${o.idpSsoUrl ?? 'https://idp.example.test/sso'},
          ${o.idpCertificate ?? 'PLACEHOLDER-CERTIFICATE'},
          ${o.spEntityId ?? 'https://sp.example.test/entity'},
          ${o.spAcsUrl ?? 'https://sp.example.test/acs'},
          ${JSON.stringify(o.attributeMapping ?? {})}::jsonb,
          ${o.enabled ?? true},
          ${o.autoProvisionUsers ?? true},
          ${o.autoAddToTeam ?? true},
          ${o.defaultRole ?? 'member'}
        ) RETURNING id`
  );
  return (result.rows[0] as { id: string }).id;
}

export async function createUser(
  sut: Sut,
  email: string,
  opts: { ssoProvider?: string | null; ssoSubjectId?: string | null; name?: string } = {}
): Promise<string> {
  const result = await sut.db.execute(
    sql`INSERT INTO users (email, name, email_verified, sso_provider, sso_subject_id)
        VALUES (${email}, ${opts.name ?? 'Integration User'}, true,
                ${opts.ssoProvider ?? null}, ${opts.ssoSubjectId ?? null})
        RETURNING id`
  );
  return (result.rows[0] as { id: string }).id;
}

export async function addTeamMember(
  sut: Sut,
  teamId: string,
  userId: string,
  role = 'member'
): Promise<void> {
  await sut.db.execute(
    sql`INSERT INTO team_members (team_id, user_id, role) VALUES (${teamId}, ${userId}, ${role})`
  );
}

export interface SsoSessionRow {
  id: string;
  status: string;
  user_id: string | null;
  relay_state: string | null;
  ip_address: string | null;
  user_agent: string | null;
  completed_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export async function readSession(sut: Sut, sessionId: string): Promise<SsoSessionRow> {
  const result = await sut.db.execute(
    sql`SELECT id, status, user_id, relay_state, host(ip_address) AS ip_address, user_agent,
               completed_at, created_at, updated_at
        FROM sso_sessions WHERE id = ${sessionId}`
  );
  if (result.rows.length === 0) throw new Error(`no sso_sessions row ${sessionId}`);
  return result.rows[0] as unknown as SsoSessionRow;
}

export async function countSessions(
  sut: Sut,
  ssoConfigId: string,
  requestId: string,
  status?: string
): Promise<number> {
  const result = status
    ? await sut.db.execute(
        sql`SELECT COUNT(*)::int AS n FROM sso_sessions
            WHERE sso_config_id = ${ssoConfigId} AND request_id = ${requestId}
              AND status = ${status}`
      )
    : await sut.db.execute(
        sql`SELECT COUNT(*)::int AS n FROM sso_sessions
            WHERE sso_config_id = ${ssoConfigId} AND request_id = ${requestId}`
      );
  return (result.rows[0] as { n: number }).n;
}
