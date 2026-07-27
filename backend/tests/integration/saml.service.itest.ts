/**
 * `saml.service.ts` against a real PostgreSQL.
 *
 * Two things live here that the unit suite structurally cannot cover:
 *
 * 1. THE FULL ACS PATH, executed. `processSAMLResponse` runs end to end against
 *    real rows — getSSOConfigById, the session consume (`removeAsync`, which
 *    writes `sso_sessions.updated_at`), the assertion-ID claim (a real unique
 *    constraint), the team-scoped user lookup, and the promotion to 'completed'
 *    (which writes `updated_at` again). Every one of those statements is a
 *    string the unit mock accepts without executing.
 *
 * 2. THE TEAM-SCOPE PREDICATE. `resolveSSOUser` scopes the user lookup with
 *    `EXISTS (SELECT 1 FROM team_members ...)`. That clause is the control that
 *    stops a team admin who owns `idp_certificate` from self-signing an
 *    assertion for any address on the platform. Against the mock, membership is
 *    decided in JavaScript by the fake, so deleting the EXISTS clause changes
 *    nothing and the control is untested. Here the database decides, so a user
 *    who belongs to a DIFFERENT team must not resolve.
 *
 * Only `utils/logger.js` is mocked, and only because `rejectSaml` puts the
 * structured rejection `reason` in the log and nowhere else — the client always
 * gets one constant message. Asserting the reason is what makes each rejection
 * attributable to the gate under test rather than to the SSO kill-switch.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi, inject } from 'vitest';
import { randomUUID } from 'node:crypto';

const { loggerCalls } = vi.hoisted(() => ({
  loggerCalls: [] as { level: string; args: unknown[] }[],
}));

vi.mock('../../src/utils/logger.js', () => {
  const record = (level: string) => (...args: unknown[]) => {
    loggerCalls.push({ level, args });
  };
  return {
    createLogger: () => ({
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    }),
  };
});

import {
  IDP_ENTITY_ID,
  IDP_PUBLIC_KEY_PEM,
  SP_ACS_URL,
  SP_ENTITY_ID,
  toPostBody,
  validSignedResponse,
} from '../../src/services/sso/__fixtures__/saml-fixtures.js';
import {
  addTeamMember,
  connectSut,
  createTeam,
  createUser,
  readSession,
  sql,
  uniqueEmail,
  type Sut,
} from './support/harness.js';

const pgFresh = inject('pgFresh');
const pgSkipReason = inject('pgSkipReason');

const nextRequestId = () => `_req-${randomUUID()}`;
const nextAssertionId = () => `_assert-${randomUUID()}`;

/** The `reason` field of the single `SAML assertion rejected` warn line. */
function rejectionReason(): string | undefined {
  const line = loggerCalls
    .filter((c) => c.level === 'warn' && c.args[1] === 'SAML assertion rejected')
    .at(-1);
  return (line?.args[0] as { reason?: string } | undefined)?.reason;
}

describe.skipIf(!pgFresh)(
  `saml.service against real PostgreSQL${pgSkipReason ? ` — SKIPPED: ${pgSkipReason}` : ''}`,
  () => {
    let sut: Sut;
    /** The team + configuration the signed fixtures are built for. */
    let teamId: string;
    let configId: string;

    /** Insert a configuration matching the fixture's signed values exactly. */
    async function createFixtureConfig(
      team: string,
      o: { autoProvisionUsers?: boolean; autoAddToTeam?: boolean; enabled?: boolean } = {}
    ): Promise<string> {
      const result = await sut.db.execute(
        sql`INSERT INTO sso_configurations (
              team_id, idp_entity_id, idp_sso_url, idp_certificate,
              sp_entity_id, sp_acs_url, attribute_mapping,
              enabled, auto_provision_users, auto_add_to_team, default_role
            ) VALUES (
              ${team}, ${IDP_ENTITY_ID}, 'https://idp.example.test/sso', ${IDP_PUBLIC_KEY_PEM},
              ${SP_ENTITY_ID}, ${SP_ACS_URL}, '{}'::jsonb,
              ${o.enabled ?? true}, ${o.autoProvisionUsers ?? true}, ${o.autoAddToTeam ?? true},
              'member'
            ) RETURNING id`
      );
      return (result.rows[0] as { id: string }).id;
    }

    /** Create the pending session a valid ACS POST must consume. */
    async function openSession(cfg: string, requestId: string, relayState?: string) {
      const provider = new sut.cache.SsoSessionCacheProvider(cfg, { relayState });
      const saved = await provider.saveAsync(requestId, new Date().toISOString());
      expect(saved).not.toBeNull();
      const row = await sut.db.execute(
        sql`SELECT id FROM sso_sessions WHERE sso_config_id = ${cfg} AND request_id = ${requestId}`
      );
      return (row.rows[0] as { id: string }).id;
    }

    beforeAll(async () => {
      sut = await connectSut(pgFresh as string);
      teamId = await createTeam(sut, 'saml-service-team');
      configId = await createFixtureConfig(teamId);
    });

    afterAll(async () => {
      await sut?.close();
    });

    beforeEach(() => {
      loggerCalls.length = 0;
    });

    // ==================================================================
    // Configuration CRUD — real rows, real ON CONFLICT, real rowCount
    // ==================================================================

    describe('configuration read/write', () => {
      it('getSSOConfig maps every column of a real row', async () => {
        const config = await sut.service.getSSOConfig(teamId);
        expect(config).not.toBeNull();
        expect(config!.id).toBe(configId);
        expect(config!.teamId).toBe(teamId);
        expect(config!.providerType).toBe('saml');
        expect(config!.enabled).toBe(true);
        expect(config!.idpCertificate).toBe(IDP_PUBLIC_KEY_PEM);
        expect(config!.spAcsUrl).toBe(SP_ACS_URL);
        // jsonb round-trips as an object, not a string — the mock never proved this.
        expect(config!.attributeMapping).toEqual({});
        expect(config!.autoAddToTeam).toBe(true);
        expect(config!.allowUnencryptedAssertion).toBe(false);
      });

      it('getSSOConfig returns null for a team with no configuration', async () => {
        expect(await sut.service.getSSOConfig(await createTeam(sut, 'no-sso'))).toBeNull();
      });

      it('getSSOConfigById returns the same row, and null for an unknown id', async () => {
        const byId = await sut.service.getSSOConfigById(configId);
        expect(byId?.teamId).toBe(teamId);
        expect(await sut.service.getSSOConfigById(randomUUID())).toBeNull();
      });

      it('upsertSSOConfig inserts, then UPDATEs on the team unique constraint', async () => {
        const team = await createTeam(sut, 'upsert-team');
        const inserted = await sut.service.upsertSSOConfig(team, {
          idpEntityId: 'https://idp.one.test/entity',
          idpSsoUrl: 'https://idp.one.test/sso',
          idpCertificate: 'CERT-ONE',
          spEntityId: 'https://sp.test/entity',
          spAcsUrl: 'https://sp.test/acs',
          attributeMapping: { email: 'mail' },
          forceAuthn: true,
          autoProvisionUsers: false,
          defaultRole: 'admin',
        });
        expect(inserted.idpCertificate).toBe('CERT-ONE');
        expect(inserted.attributeMapping).toEqual({ email: 'mail' });
        expect(inserted.forceAuthn).toBe(true);
        expect(inserted.autoProvisionUsers).toBe(false);
        expect(inserted.defaultRole).toBe('admin');

        const updated = await sut.service.upsertSSOConfig(team, {
          idpEntityId: 'https://idp.two.test/entity',
          idpSsoUrl: 'https://idp.two.test/sso',
          idpCertificate: 'CERT-TWO',
          spEntityId: 'https://sp.test/entity',
          spAcsUrl: 'https://sp.test/acs',
        });
        // ON CONFLICT (team_id) DO UPDATE — one row, not two.
        expect(updated.id).toBe(inserted.id);
        expect(updated.idpCertificate).toBe('CERT-TWO');
        const count = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM sso_configurations WHERE team_id = ${team}`
        );
        expect((count.rows[0] as { n: number }).n).toBe(1);
      });

      it('toggleSSO flips enabled, and throws NotFoundError when no row matches', async () => {
        const team = await createTeam(sut, 'toggle-team');
        await sut.service.upsertSSOConfig(team, {
          idpEntityId: 'e',
          idpSsoUrl: 'u',
          idpCertificate: 'c',
          spEntityId: 'se',
          spAcsUrl: 'sa',
        });

        await sut.service.toggleSSO(team, true);
        expect((await sut.service.getSSOConfig(team))!.enabled).toBe(true);
        await sut.service.toggleSSO(team, false);
        expect((await sut.service.getSSOConfig(team))!.enabled).toBe(false);

        // rowCount === 0 is a real driver value here, not a mock's.
        await expect(sut.service.toggleSSO(randomUUID(), true)).rejects.toBeInstanceOf(
          sut.errors.NotFoundError
        );
      });

      it('deleteSSOConfig removes the row and cascades to its sessions', async () => {
        const team = await createTeam(sut, 'delete-team');
        const cfg = await createFixtureConfig(team);
        await openSession(cfg, nextRequestId());

        await sut.service.deleteSSOConfig(team);

        expect(await sut.service.getSSOConfig(team)).toBeNull();
        const sessions = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM sso_sessions WHERE sso_config_id = ${cfg}`
        );
        expect((sessions.rows[0] as { n: number }).n).toBe(0);
      });

      it('initiateSAMLLogin persists a pending session for the request it returns', async () => {
        const config = (await sut.service.getSSOConfigById(configId))!;
        const { redirectUrl, requestId } = await sut.service.initiateSAMLLogin(
          config,
          '/dashboard',
          '198.51.100.7',
          'integration-agent'
        );
        expect(redirectUrl).toContain('SAMLRequest=');

        const rows = await sut.db.execute(
          sql`SELECT status, relay_state, host(ip_address) AS ip, user_agent
              FROM sso_sessions WHERE sso_config_id = ${configId} AND request_id = ${requestId}`
        );
        expect(rows.rows).toHaveLength(1);
        const row = rows.rows[0] as Record<string, unknown>;
        expect(row.status).toBe('pending');
        expect(row.relay_state).toBe('/dashboard');
        expect(row.ip).toBe('198.51.100.7');
        expect(row.user_agent).toBe('integration-agent');
      });
    });

    // ==================================================================
    // The full ACS path
    // ==================================================================

    describe('processSAMLResponse end to end', () => {
      it('authenticates a linked member of the configuration team and completes the session', async () => {
        const email = uniqueEmail('linked');
        const userId = await createUser(sut, email, {
          ssoProvider: 'saml',
          ssoSubjectId: email,
        });
        await addTeamMember(sut, teamId, userId);

        const requestId = nextRequestId();
        const sessionId = await openSession(configId, requestId, '/projects');
        const before = await readSession(sut, sessionId);
        await new Promise((r) => setTimeout(r, 25));

        const xml = validSignedResponse({
          inResponseTo: requestId,
          assertionId: nextAssertionId(),
          email,
        });
        const result = await sut.service.processSAMLResponse(toPostBody(xml), configId);

        expect(result.user.id).toBe(userId);
        expect(result.user.email).toBe(email);
        expect(result.isNewUser).toBe(false);
        expect(result.tokens.accessToken).toBeTypeOf('string');
        // H-7: the RelayState delivered is the one THIS SP stored, read back out
        // of the row `removeAsync` consumed.
        expect(result.relayState).toBe('/projects');

        // The two writes that could not execute before migration 024.
        const after = await readSession(sut, sessionId);
        expect(after.status).toBe('completed');
        expect(after.user_id).toBe(userId);
        expect(after.completed_at).not.toBeNull();
        expect(new Date(after.updated_at).getTime()).toBeGreaterThan(
          new Date(before.updated_at).getTime()
        );
      });

      it('records the consumed assertion ID so the same assertion cannot be used twice', async () => {
        const email = uniqueEmail('replay');
        const userId = await createUser(sut, email, { ssoProvider: 'saml', ssoSubjectId: email });
        await addTeamMember(sut, teamId, userId);

        const assertionId = nextAssertionId();
        const firstRequest = nextRequestId();
        await openSession(configId, firstRequest);
        await sut.service.processSAMLResponse(
          toPostBody(validSignedResponse({ inResponseTo: firstRequest, assertionId, email })),
          configId
        );

        const claimed = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM saml_assertion_replay
              WHERE sso_config_id = ${configId} AND assertion_id = ${assertionId}`
        );
        expect((claimed.rows[0] as { n: number }).n).toBe(1);

        // A FRESH session, so the session gate cannot be what rejects: only the
        // assertion-ID unique constraint can.
        const secondRequest = nextRequestId();
        const secondSessionId = await openSession(configId, secondRequest);
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(validSignedResponse({ inResponseTo: secondRequest, assertionId, email })),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('assertion_replayed');
        // Rejected after the consume, so the session must NOT read as a login.
        expect((await readSession(sut, secondSessionId)).status).toBe('failed');
      });

      it('rejects a second POST of the same response — the session is single-use', async () => {
        const email = uniqueEmail('session-replay');
        const userId = await createUser(sut, email, { ssoProvider: 'saml', ssoSubjectId: email });
        await addTeamMember(sut, teamId, userId);

        const requestId = nextRequestId();
        await openSession(configId, requestId);
        const body = toPostBody(
          validSignedResponse({ inResponseTo: requestId, assertionId: nextAssertionId(), email })
        );

        await expect(sut.service.processSAMLResponse(body, configId)).resolves.toBeTruthy();
        await expect(sut.service.processSAMLResponse(body, configId)).rejects.toBeInstanceOf(
          sut.errors.UnauthorizedError
        );
        // `library_validation_failed`, not `session_not_consumed`: the row is no
        // longer 'pending', so node-saml's own InResponseTo cross-check fails at
        // `getAsync` — inside the library, before Step 4 is reached. Attributable
        // because the identical body authenticated one call earlier.
        expect(rejectionReason()).toBe('library_validation_failed');
        // The completed row was NOT re-consumed or re-promoted by the replay.
        const rows = await sut.db.execute(
          sql`SELECT status FROM sso_sessions
              WHERE sso_config_id = ${configId} AND request_id = ${requestId}`
        );
        expect(rows.rows.map((r) => (r as { status: string }).status)).toEqual(['completed']);
      });

      it('rejects a valid, correctly signed assertion for which no session was ever opened', async () => {
        const email = uniqueEmail('no-session');
        const userId = await createUser(sut, email, { ssoProvider: 'saml', ssoSubjectId: email });
        await addTeamMember(sut, teamId, userId);
        const requestId = nextRequestId();

        // Same builder that authenticates elsewhere in this file; the ONLY
        // difference is that no pending row exists. Rejected by node-saml's own
        // InResponseTo cross-check, which reads through our `getAsync`.
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('library_validation_failed');
        // Nothing was invented: no row appeared for a request we never issued.
        const rows = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM sso_sessions WHERE request_id = ${requestId}`
        );
        expect((rows.rows[0] as { n: number }).n).toBe(0);
      });

      it('rejects when the configuration is disabled', async () => {
        const team = await createTeam(sut, 'disabled-team');
        const cfg = await createFixtureConfig(team, { enabled: false });
        const requestId = nextRequestId();
        await openSession(cfg, requestId);

        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email: uniqueEmail('disabled'),
              })
            ),
            cfg
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('config_disabled');
      });

      it('rejects when the configuration id does not exist', async () => {
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(validSignedResponse({ assertionId: nextAssertionId() })),
            randomUUID()
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('config_missing');
      });
    });

    // ==================================================================
    // The team-scope predicate — flagged as UNCOVERED by the unit suite
    // ==================================================================

    describe('team-scoped identity resolution', () => {
      it('a user in ANOTHER team does not resolve, even fully SSO-linked with a matching subject', async () => {
        // This is the account-takeover case the EXISTS clause exists to stop:
        // signature verification passes because the attacker admin controls
        // `idp_certificate`, so the ONLY thing standing between the assertion
        // and the victim's account is team membership, enforced by the database.
        const email = uniqueEmail('other-team');
        const victimTeam = await createTeam(sut, 'victim-team');
        const victimId = await createUser(sut, email, {
          ssoProvider: 'saml',
          ssoSubjectId: email,
        });
        await addTeamMember(sut, victimTeam, victimId);
        // Deliberately NOT a member of `teamId`, which owns `configId`.

        const requestId = nextRequestId();
        const sessionId = await openSession(configId, requestId);

        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('user_not_in_team');

        // No token, no promotion, and no duplicate account for the victim.
        expect((await readSession(sut, sessionId)).status).toBe('failed');
        const users = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM users WHERE email = ${email}`
        );
        expect((users.rows[0] as { n: number }).n).toBe(1);
        // And the victim was not dragged into the attacker's team.
        const membership = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM team_members
              WHERE user_id = ${victimId} AND team_id = ${teamId}`
        );
        expect((membership.rows[0] as { n: number }).n).toBe(0);
      });

      it('the SAME user resolves once added to the configuration team', async () => {
        // The paired positive: only team membership differs between this and the
        // case above, so the EXISTS clause is what the pair is measuring.
        const email = uniqueEmail('joins-team');
        const otherTeam = await createTeam(sut, 'origin-team');
        const userId = await createUser(sut, email, { ssoProvider: 'saml', ssoSubjectId: email });
        await addTeamMember(sut, otherTeam, userId);

        const firstRequest = nextRequestId();
        await openSession(configId, firstRequest);
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: firstRequest,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);

        await addTeamMember(sut, teamId, userId);

        const secondRequest = nextRequestId();
        await openSession(configId, secondRequest);
        const result = await sut.service.processSAMLResponse(
          toPostBody(
            validSignedResponse({
              inResponseTo: secondRequest,
              assertionId: nextAssertionId(),
              email,
            })
          ),
          configId
        );
        expect(result.user.id).toBe(userId);
        expect(result.isNewUser).toBe(false);
      });

      it('a team member with a local password is NOT silently adopted into SSO', async () => {
        const email = uniqueEmail('local-password');
        const userId = await createUser(sut, email); // sso_provider IS NULL
        await addTeamMember(sut, teamId, userId);

        const requestId = nextRequestId();
        await openSession(configId, requestId);
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('user_not_sso_linked');

        const row = await sut.db.execute(
          sql`SELECT sso_provider FROM users WHERE id = ${userId}`
        );
        expect((row.rows[0] as { sso_provider: string | null }).sso_provider).toBeNull();
      });

      it('a linked team member whose stored subject id differs is rejected', async () => {
        const email = uniqueEmail('subject-mismatch');
        const userId = await createUser(sut, email, {
          ssoProvider: 'saml',
          ssoSubjectId: 'some-other-subject',
        });
        await addTeamMember(sut, teamId, userId);

        const requestId = nextRequestId();
        await openSession(configId, requestId);
        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            configId
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('user_not_sso_linked');
      });

      it('auto-provisions an unknown address into the configuration team', async () => {
        const email = uniqueEmail('provisioned');
        const requestId = nextRequestId();
        const sessionId = await openSession(configId, requestId);

        const result = await sut.service.processSAMLResponse(
          toPostBody(
            validSignedResponse({
              inResponseTo: requestId,
              assertionId: nextAssertionId(),
              email,
            })
          ),
          configId
        );
        expect(result.isNewUser).toBe(true);

        const created = await sut.db.execute(
          sql`SELECT id, email, name, sso_provider, sso_subject_id, email_verified
              FROM users WHERE email = ${email}`
        );
        const row = created.rows[0] as Record<string, unknown>;
        expect(row.id).toBe(result.user.id);
        expect(row.sso_provider).toBe('saml');
        expect(row.sso_subject_id).toBe(email);
        expect(row.email_verified).toBe(true);
        expect(row.name).toBe('Alice Example');

        const membership = await sut.db.execute(
          sql`SELECT role FROM team_members WHERE team_id = ${teamId} AND user_id = ${result.user.id}`
        );
        expect(membership.rows).toHaveLength(1);
        expect((membership.rows[0] as { role: string }).role).toBe('member');

        expect((await readSession(sut, sessionId)).status).toBe('completed');
      });

      it('refuses to provision when auto_provision_users is off', async () => {
        const team = await createTeam(sut, 'no-provision-team');
        const cfg = await createFixtureConfig(team, { autoProvisionUsers: false });
        const email = uniqueEmail('no-provision');
        const requestId = nextRequestId();
        await openSession(cfg, requestId);

        await expect(
          sut.service.processSAMLResponse(
            toPostBody(
              validSignedResponse({
                inResponseTo: requestId,
                assertionId: nextAssertionId(),
                email,
              })
            ),
            cfg
          )
        ).rejects.toBeInstanceOf(sut.errors.UnauthorizedError);
        expect(rejectionReason()).toBe('user_not_provisionable');

        const users = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM users WHERE email = ${email}`
        );
        expect((users.rows[0] as { n: number }).n).toBe(0);
      });

      it('provisions without team membership when auto_add_to_team is off', async () => {
        const team = await createTeam(sut, 'no-add-team');
        const cfg = await createFixtureConfig(team, { autoAddToTeam: false });
        const email = uniqueEmail('no-add');
        const requestId = nextRequestId();
        await openSession(cfg, requestId);

        const result = await sut.service.processSAMLResponse(
          toPostBody(
            validSignedResponse({
              inResponseTo: requestId,
              assertionId: nextAssertionId(),
              email,
            })
          ),
          cfg
        );
        expect(result.isNewUser).toBe(true);

        const membership = await sut.db.execute(
          sql`SELECT COUNT(*)::int AS n FROM team_members
              WHERE team_id = ${team} AND user_id = ${result.user.id}`
        );
        expect((membership.rows[0] as { n: number }).n).toBe(0);
      });

      it('matches the address case-insensitively, as the lowercased lookup requires', async () => {
        const email = uniqueEmail('MixedCase').toUpperCase();
        const lower = email.toLowerCase();
        const userId = await createUser(sut, lower, {
          ssoProvider: 'saml',
          ssoSubjectId: email,
        });
        await addTeamMember(sut, teamId, userId);

        const requestId = nextRequestId();
        await openSession(configId, requestId);
        const result = await sut.service.processSAMLResponse(
          toPostBody(
            validSignedResponse({
              inResponseTo: requestId,
              assertionId: nextAssertionId(),
              email,
              nameId: email,
            })
          ),
          configId
        );
        expect(result.user.id).toBe(userId);
      });
    });
  }
);
