/**
 * SAML 2.0 SSO Service
 *
 * Handles SP-initiated SAML authentication flow:
 *   1. Generate AuthnRequest → redirect user to IdP
 *   2. IdP authenticates user → POST assertion to ACS endpoint
 *   3. Validate assertion → find or create user → issue JWT
 */

import crypto from 'crypto';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import { generateTokens, type AuthTokens, type UserData } from '../auth.service.js';
import { NotFoundError } from '../../middleware/errorHandler.js';
import { ssoEnabled } from '../../config/env.js';
import {
  SsoSessionCacheProvider,
  promoteSessionToCompleted,
} from './sso-session-cache.js';
import {
  assertionReplayExpiry,
  checkConditionsWindow,
  checkDestination,
  checkIssuer,
  checkRecipient,
  checkSubjectInResponseTo,
  correlationOf,
  createSamlValidator,
  decodeAndScreenResponse,
  envelopeInResponseTo,
  parseResponseDom,
  pinAlgorithms,
  readVerifiedAssertion,
  rejectSaml,
  validateSignedResponse,
  type SamlLogContext,
} from './saml-validator.js';
import { claimAssertionId, maybeCleanupExpiredAssertionIds } from './assertion-replay.js';

const logger = createLogger('saml-service');

/** Row shape for sso_configurations SELECT */
interface SSOConfigRow {
  id: string;
  team_id: string;
  provider_type: string;
  enabled: boolean;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_certificate: string;
  idp_metadata_url: string | null;
  sp_entity_id: string;
  sp_acs_url: string;
  attribute_mapping: Record<string, string>;
  force_authn: boolean;
  allow_unencrypted_assertion: boolean;
  sign_authn_request: boolean;
  default_role: string;
  auto_provision_users: boolean;
  auto_add_to_team: boolean;
}

/** Row shape for RETURNING id */
interface IdRow {
  id: string;
}

/** Row shape for user lookup */
interface UserRow {
  id: string;
  email: string;
  name: string;
  created_at: Date;
  sso_provider: string | null;
  sso_subject_id: string | null;
}

export interface SSOConfig {
  id: string;
  teamId: string;
  providerType: string;
  enabled: boolean;
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertificate: string;
  idpMetadataUrl: string | null;
  spEntityId: string;
  spAcsUrl: string;
  attributeMapping: Record<string, string>;
  forceAuthn: boolean;
  allowUnencryptedAssertion: boolean;
  signAuthnRequest: boolean;
  defaultRole: string;
  autoProvisionUsers: boolean;
  autoAddToTeam: boolean;
}

export interface SAMLAssertion {
  nameId: string;
  nameIdFormat: string;
  sessionIndex: string;
  /**
   * Attribute names come from the (unauthenticated) SAML Response, so they are
   * held in a Map rather than a plain object: a Map has no prototype chain to
   * write through and no inherited keys to read back by accident.
   */
  attributes: Map<string, string | string[]>;
  issuer: string;
  inResponseTo: string;
  notBefore?: string;
  notOnOrAfter?: string;
}

/**
 * Get SSO configuration for a team
 */
export async function getSSOConfig(teamId: string): Promise<SSOConfig | null> {
  const result = await db.execute(
    sql`SELECT id, team_id, provider_type, enabled,
               idp_entity_id, idp_sso_url, idp_certificate, idp_metadata_url,
               sp_entity_id, sp_acs_url, attribute_mapping,
               force_authn, allow_unencrypted_assertion, sign_authn_request,
               default_role, auto_provision_users, auto_add_to_team
        FROM sso_configurations WHERE team_id = ${teamId}`
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0] as unknown as SSOConfigRow;
  return mapSSOConfigRow(row);
}

/**
 * Get SSO config by ID
 */
export async function getSSOConfigById(configId: string): Promise<SSOConfig | null> {
  const result = await db.execute(
    sql`SELECT id, team_id, provider_type, enabled,
               idp_entity_id, idp_sso_url, idp_certificate, idp_metadata_url,
               sp_entity_id, sp_acs_url, attribute_mapping,
               force_authn, allow_unencrypted_assertion, sign_authn_request,
               default_role, auto_provision_users, auto_add_to_team
        FROM sso_configurations WHERE id = ${configId}`
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0] as unknown as SSOConfigRow;
  return mapSSOConfigRow(row);
}

/** Map a raw DB row to the SSOConfig interface */
function mapSSOConfigRow(row: SSOConfigRow): SSOConfig {
  return {
    id: row.id,
    teamId: row.team_id,
    providerType: row.provider_type,
    enabled: row.enabled,
    idpEntityId: row.idp_entity_id,
    idpSsoUrl: row.idp_sso_url,
    idpCertificate: row.idp_certificate,
    idpMetadataUrl: row.idp_metadata_url,
    spEntityId: row.sp_entity_id,
    spAcsUrl: row.sp_acs_url,
    attributeMapping: row.attribute_mapping,
    forceAuthn: row.force_authn,
    allowUnencryptedAssertion: row.allow_unencrypted_assertion,
    signAuthnRequest: row.sign_authn_request,
    defaultRole: row.default_role,
    autoProvisionUsers: row.auto_provision_users,
    autoAddToTeam: row.auto_add_to_team,
  };
}

/**
 * Create or update SSO configuration for a team.
 * Requires Team or Enterprise tier.
 */
export async function upsertSSOConfig(
  teamId: string,
  config: {
    idpEntityId: string;
    idpSsoUrl: string;
    idpCertificate: string;
    idpMetadataUrl?: string;
    spEntityId: string;
    spAcsUrl: string;
    attributeMapping?: Record<string, string>;
    forceAuthn?: boolean;
    signAuthnRequest?: boolean;
    autoProvisionUsers?: boolean;
    defaultRole?: string;
  }
): Promise<SSOConfig> {
  const result = await db.execute(
    sql`INSERT INTO sso_configurations (
          team_id, idp_entity_id, idp_sso_url, idp_certificate,
          idp_metadata_url, sp_entity_id, sp_acs_url,
          attribute_mapping, force_authn, sign_authn_request,
          auto_provision_users, default_role
        ) VALUES (
          ${teamId}, ${config.idpEntityId}, ${config.idpSsoUrl}, ${config.idpCertificate},
          ${config.idpMetadataUrl || null}, ${config.spEntityId}, ${config.spAcsUrl},
          ${JSON.stringify(config.attributeMapping || {})}::jsonb,
          ${config.forceAuthn ?? false}, ${config.signAuthnRequest ?? true},
          ${config.autoProvisionUsers ?? true}, ${config.defaultRole || 'member'}
        )
        ON CONFLICT (team_id) DO UPDATE SET
          idp_entity_id = EXCLUDED.idp_entity_id,
          idp_sso_url = EXCLUDED.idp_sso_url,
          idp_certificate = EXCLUDED.idp_certificate,
          idp_metadata_url = EXCLUDED.idp_metadata_url,
          sp_entity_id = EXCLUDED.sp_entity_id,
          sp_acs_url = EXCLUDED.sp_acs_url,
          attribute_mapping = EXCLUDED.attribute_mapping,
          force_authn = EXCLUDED.force_authn,
          sign_authn_request = EXCLUDED.sign_authn_request,
          auto_provision_users = EXCLUDED.auto_provision_users,
          default_role = EXCLUDED.default_role,
          updated_at = NOW()
        RETURNING *`
  );

  const row = result.rows[0] as unknown as IdRow;
  logger.info({ teamId, configId: row.id }, 'SSO configuration saved');

  return getSSOConfigById(row.id) as Promise<SSOConfig>;
}

/**
 * Enable or disable SSO for a team
 */
export async function toggleSSO(teamId: string, enabled: boolean): Promise<void> {
  const result = await db.execute(
    sql`UPDATE sso_configurations SET enabled = ${enabled}, updated_at = NOW()
        WHERE team_id = ${teamId}`
  );

  if (result.rowCount === 0) {
    throw new NotFoundError('SSO configuration not found for this team');
  }

  logger.info({ teamId, enabled }, 'SSO toggled');
}

/**
 * Generate a SAML AuthnRequest and return the redirect URL.
 * Creates an sso_session record to track the in-flight auth flow.
 */
export async function initiateSAMLLogin(
  ssoConfig: SSOConfig,
  relayState?: string,
  ipAddress?: string,
  userAgent?: string
): Promise<{ redirectUrl: string; requestId: string }> {
  // Kill-switch, service layer (§B.13 layer 3). This is the durable one: it
  // holds for direct service calls, future routes, queue workers and tests,
  // independent of how the router happens to be mounted.
  if (!ssoEnabled) {
    rejectSaml('sso_disabled', {
      ssoConfigId: ssoConfig.id,
      teamId: ssoConfig.teamId,
      correlation: 'none',
    });
  }

  const requestId = `_${crypto.randomUUID()}`;

  // Create session to track this auth flow. Routed through the cache provider
  // so one implementation owns the table and node-saml's `getAsync` observes
  // exactly the rows this writes.
  const provider = new SsoSessionCacheProvider(ssoConfig.id, {
    relayState,
    ipAddress,
    userAgent,
  });
  await provider.saveAsync(requestId, new Date().toISOString());

  // Build AuthnRequest XML
  const issueInstant = new Date().toISOString();
  const authnRequest = `
    <samlp:AuthnRequest
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="${requestId}"
      Version="2.0"
      IssueInstant="${issueInstant}"
      Destination="${ssoConfig.idpSsoUrl}"
      AssertionConsumerServiceURL="${ssoConfig.spAcsUrl}"
      ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      ${ssoConfig.forceAuthn ? 'ForceAuthn="true"' : ''}>
      <saml:Issuer>${ssoConfig.spEntityId}</saml:Issuer>
      <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
    </samlp:AuthnRequest>`.trim();

  // Deflate + base64 encode for HTTP-Redirect binding
  const { deflateRaw } = await import('zlib');
  const { promisify } = await import('util');
  const deflate = promisify(deflateRaw);
  const deflated = await deflate(Buffer.from(authnRequest));
  const encoded = deflated.toString('base64');
  const samlRequest = encodeURIComponent(encoded);

  let redirectUrl = `${ssoConfig.idpSsoUrl}?SAMLRequest=${samlRequest}`;
  if (relayState) {
    redirectUrl += `&RelayState=${encodeURIComponent(relayState)}`;
  }

  logger.info({
    requestId,
    idpUrl: ssoConfig.idpSsoUrl,
    teamId: ssoConfig.teamId,
  }, 'SAML login initiated');

  return { redirectUrl, requestId };
}

/**
 * Process a SAML Response (assertion) from the IdP.
 *
 * Every assertion reaching this function has its signature verified against the
 * pinned `idp_certificate` before any field of it is believed. There is no
 * branch anywhere that asks whether a signature is present: an unsigned
 * assertion, or one signed by any other key, is rejected by
 * `validateSignedResponse`.
 *
 * The order of the steps below is load-bearing and must not be rearranged —
 * in particular the session consume produces the `consumedRequestId` that the
 * request-binding check compares against, so it has to precede it.
 */
export async function processSAMLResponse(
  samlResponse: string,
  ssoConfigId: string
): Promise<{
  user: UserData;
  tokens: AuthTokens;
  isNewUser: boolean;
  /**
   * The `relay_state` THIS SP stored when it issued the AuthnRequest — never
   * the `RelayState` field of the POST body. See H-7 and the ACS route.
   */
  relayState: string | null;
}> {
  const ctx: SamlLogContext = { ssoConfigId, teamId: null, correlation: 'none' };

  if (!ssoEnabled) rejectSaml('sso_disabled', ctx);

  const config = await getSSOConfigById(ssoConfigId);
  if (!config) rejectSaml('config_missing', ctx);
  ctx.teamId = config.teamId;
  if (!config.enabled) rejectSaml('config_disabled', ctx);

  // Size cap, decode, DTD rejection — before node-saml or any DOM parser sees
  // the body. Bounds XML-parser CPU and memory on unauthenticated input.
  const responseXml = decodeAndScreenResponse(samlResponse, ctx);

  // Step 0 — strict well-formedness screen. This MUST precede node-saml: it is
  // what stops a warning-class document (an unquoted attribute value, say) from
  // reaching `xml-crypto`'s unconfigured xmldom parser, which writes
  // attacker-chosen text to `console.warn` on an unauthenticated endpoint. No
  // value from this document informs any decision until after Step 1, so this
  // does not read unverified data — see `parseResponseDom`. The same parse then
  // serves the advisory Destination check and both algorithm pins.
  const doc = parseResponseDom(responseXml, ctx);

  const { saml, provider } = createSamlValidator(config, ctx);

  // Step 1 — signature verification. Everything after this point reads only
  // bytes that the pinned IdP certificate actually covered.
  const profile = await validateSignedResponse(saml, samlResponse, ctx);

  // Step 2 — algorithm pinning, after validation and before any identity
  // decision. Covers the assertion signature AND the envelope signature when
  // one is present.
  pinAlgorithms(doc, ctx);

  // Step 3 — structural reads and the checks the library does not perform.
  const assertion = readVerifiedAssertion(profile, ctx);
  ctx.correlation = correlationOf(assertion.subjectInResponseTo[0] ?? null);
  checkIssuer(assertion, config, ctx);
  // Our own assertion-lifetime enforcement. node-saml skips its entire
  // timestamp block for a `<Conditions>` element with no attributes.
  checkConditionsWindow(assertion, ctx);
  checkRecipient(assertion, config, ctx);
  checkDestination(doc, config, ctx);

  // Step 4 — consume the pending session, atomically and exactly once.
  // node-saml may or may not have already called `removeAsync`, depending on
  // the assertion's SubjectConfirmationData shape (`saml.js:797-830`) and on
  // whether it took the terminal catch (`saml.js:625-631`). Consume
  // unconditionally; the UPDATE is idempotent-safe because a second execution
  // matches zero rows.
  if (provider.consumedSessionId === null) {
    await provider.removeAsync(envelopeInResponseTo(doc, ctx));
  }
  const sessionId = provider.consumedSessionId;
  const consumedRequestId = provider.consumedRequestId;
  // Replay, expired, or wrong tenant.
  if (sessionId === null || consumedRequestId === null) rejectSaml('session_not_consumed', ctx);

  // Step 5 — bind the assertion to the request we actually consumed.
  checkSubjectInResponseTo(assertion, consumedRequestId, ctx);

  // Step 6 — assertion-ID single use. Independent of the session gate, so a
  // replayed assertion carrying a fresh InResponseTo is still blocked.
  const claimed = await claimAssertionId(
    config.id,
    assertion.id,
    assertionReplayExpiry(assertion)
  );
  if (!claimed) rejectSaml('assertion_replayed', ctx);

  // Step 7 — resolve the identity, scoped to this configuration's team.
  const identity = toSAMLAssertion(assertion, consumedRequestId);
  const { user, isNewUser } = await resolveSSOUser(identity, config, ctx);

  // Step 8 — promote the session. The last DB write, reached only on full
  // success, so 'completed' keeps meaning "a user actually logged in".
  const promoted = await promoteSessionToCompleted(sessionId, user.id);
  if (!promoted) {
    // Not a rejection: every security gate has already passed and the user is
    // authenticated. It IS an audit-integrity event — `sso_sessions` will
    // under-count this successful login — so it must not pass silently.
    logger.warn(
      { ssoConfigId, teamId: config.teamId, reason: 'session_promotion_missed' },
      'SSO session promotion matched no row'
    );
  }

  const tokens = generateTokens(user.id, user.email);

  logger.info({ userId: user.id, teamId: config.teamId, isNewUser }, 'SAML authentication successful');

  void maybeCleanupExpiredAssertionIds();

  return { user, tokens, isNewUser, relayState: provider.consumedRelayState };
}

/**
 * Project the structurally-read assertion onto the long-standing
 * `SAMLAssertion` shape, which the identity resolution below consumes.
 */
function toSAMLAssertion(
  assertion: ReturnType<typeof readVerifiedAssertion>,
  consumedRequestId: string
): SAMLAssertion {
  return {
    nameId: assertion.nameId,
    nameIdFormat: assertion.nameIdFormat,
    sessionIndex: assertion.sessionIndex,
    attributes: assertion.attributes,
    issuer: assertion.issuer,
    inResponseTo: consumedRequestId,
    notBefore: assertion.conditionsNotBefore,
    notOnOrAfter: assertion.conditionsNotOnOrAfter,
  };
}

/**
 * Resolve the assertion's subject to a local user, scoped to the team that owns
 * this SSO configuration.
 *
 * Signature verification alone does NOT close the account-takeover hole; it
 * only changes who can exploit it. `sso_configurations.idp_certificate` is
 * writable by any team admin while the `users` identity namespace is global, so
 * without the team scope below an attacker who configures their own team's IdP
 * can self-sign an assertion naming any address on the platform and every
 * cryptographic check passes — because they control every value being checked.
 *
 * This is the minimal closure. It does NOT close the case where an attacker
 * admin first induces the victim into their team; a verified per-configuration
 * email-domain allowlist is the control that would, and it is a deliberately
 * deferred follow-on. Keep SSO_ENABLED=false for any deployment with untrusted
 * team admins.
 */
async function resolveSSOUser(
  assertion: SAMLAssertion,
  config: SSOConfig,
  ctx: SamlLogContext
): Promise<{ user: UserData; isNewUser: boolean }> {
  const emailAttr = config.attributeMapping.email || 'email';
  const nameAttr = config.attributeMapping.name || 'name';

  let email = assertion.nameId;
  const emailVal = assertion.attributes.get(emailAttr);
  if (emailVal) {
    email = Array.isArray(emailVal) ? emailVal[0] : emailVal;
  }

  let name: string | null = null;
  const nameVal = assertion.attributes.get(nameAttr);
  if (nameVal) {
    name = Array.isArray(nameVal) ? nameVal[0] : nameVal;
  }

  if (!email) rejectSaml('email_missing', ctx);
  const emailLower = email.toLowerCase();

  const userResult = await db.execute(
    sql`SELECT u.id, u.email, u.name, u.created_at, u.sso_provider, u.sso_subject_id
        FROM users u
        WHERE u.email = ${emailLower}
          AND EXISTS (SELECT 1 FROM team_members tm
                      WHERE tm.team_id = ${config.teamId} AND tm.user_id = u.id)`
  );

  if (userResult.rows.length > 0) {
    const row = userResult.rows[0] as unknown as UserRow;

    // Linking a local-password account to a team IdP is an explicit,
    // authenticated, user-consented action — not something an unauthenticated
    // POST performs. The previous code silently adopted any matching account
    // ("UPDATE users SET sso_provider = 'saml' ... WHERE sso_provider IS NULL"),
    // which handed the account to whoever controlled the assertion.
    if (row.sso_provider !== 'saml') rejectSaml('user_not_sso_linked', ctx);
    if (row.sso_subject_id !== assertion.nameId) rejectSaml('user_not_sso_linked', ctx);

    return {
      user: {
        id: row.id,
        email: row.email,
        name: row.name,
        createdAt: row.created_at,
      },
      isNewUser: false,
    };
  }

  // No user in this team. Before provisioning, make sure the address does not
  // already belong to someone OUTSIDE it — otherwise the "user not found" path
  // would create a duplicate account for a victim's address, or collide on the
  // unique email index.
  const foreignUser = await db.execute(
    sql`SELECT id FROM users WHERE email = ${emailLower}`
  );
  if (foreignUser.rows.length > 0) rejectSaml('user_not_in_team', ctx);

  if (!config.autoProvisionUsers) rejectSaml('user_not_provisionable', ctx);

  // NEW-3 — this INSERT sits on an unauthenticated path and can fail for a
  // reason that is not an AppError: two concurrent first-time SSO logins for the
  // same address, or a race against self-registration, both raise a unique
  // violation on `users.email`. `errorHandler.ts:84` echoes `err.message` for
  // non-AppError throws in dev, so a raw `pg` error here is a schema-disclosure
  // channel. The catch is bare — no binding — so there is no error variable in
  // scope for a later edit to log or rethrow.
  let createResult;
  try {
    createResult = await db.execute(
      sql`INSERT INTO users (email, name, email_verified, sso_provider, sso_subject_id)
          VALUES (${emailLower}, ${name}, true, 'saml', ${assertion.nameId})
          RETURNING id, email, name, created_at`
    );
  } catch {
    rejectSaml('user_provisioning_failed', ctx);
  }
  if (createResult.rows.length === 0) rejectSaml('user_provisioning_failed', ctx);
  const created = createResult.rows[0] as unknown as UserRow;

  if (config.autoAddToTeam) {
    await db.execute(
      sql`INSERT INTO team_members (team_id, user_id, role)
          VALUES (${config.teamId}, ${created.id}, ${config.defaultRole})
          ON CONFLICT DO NOTHING`
    );
  }

  logger.info(
    { userId: created.id, teamId: config.teamId },
    'SSO user auto-provisioned'
  );

  return {
    user: {
      id: created.id,
      email: created.email,
      name: created.name,
      createdAt: created.created_at,
    },
    isNewUser: true,
  };
}

/**
 * Generate SP metadata XML for IdP configuration
 */
export function generateSPMetadata(config: SSOConfig): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${config.spEntityId}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="${config.signAuthnRequest}"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${config.spAcsUrl}"
      index="0"
      isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
}

/**
 * Delete SSO configuration (admin action)
 */
export async function deleteSSOConfig(teamId: string): Promise<void> {
  await db.execute(
    sql`DELETE FROM sso_configurations WHERE team_id = ${teamId}`
  );
  logger.info({ teamId }, 'SSO configuration deleted');
}

export { cleanupExpiredAssertionIds } from './assertion-replay.js';

/**
 * Clean up expired SSO sessions
 */
export async function cleanupExpiredSessions(): Promise<number> {
  const result = await db.execute(
    sql`UPDATE sso_sessions SET status = 'expired'
        WHERE status = 'pending' AND created_at < NOW() - INTERVAL '10 minutes'`
  );
  return result.rowCount || 0;
}
