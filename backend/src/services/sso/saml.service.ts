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
import { NotFoundError, UnauthorizedError } from '../../middleware/errorHandler.js';

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
  const requestId = `_${crypto.randomUUID()}`;

  // Create session to track this auth flow
  await db.execute(
    sql`INSERT INTO sso_sessions (sso_config_id, request_id, relay_state, ip_address, user_agent)
        VALUES (${ssoConfig.id}, ${requestId}, ${relayState || null},
                ${ipAddress || null}::inet, ${userAgent || null})`
  );

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
 * Validates the assertion, finds or creates the user, and returns JWT tokens.
 */
export async function processSAMLResponse(
  samlResponse: string,
  ssoConfigId: string
): Promise<{ user: UserData; tokens: AuthTokens; isNewUser: boolean }> {
  const config = await getSSOConfigById(ssoConfigId);
  if (!config || !config.enabled) {
    throw new UnauthorizedError('SSO not configured or disabled');
  }

  // Decode the SAML response
  const responseXml = Buffer.from(samlResponse, 'base64').toString('utf-8');

  // Parse the assertion (simplified — production should use xml-crypto for signature validation)
  const assertion = parseSAMLAssertion(responseXml, config);

  // Verify the InResponseTo matches a pending session
  const sessionResult = await db.execute(
    sql`SELECT id FROM sso_sessions
        WHERE request_id = ${assertion.inResponseTo}
        AND sso_config_id = ${config.id}
        AND status = 'pending'
        AND created_at > NOW() - INTERVAL '10 minutes'`
  );

  if (sessionResult.rows.length === 0) {
    throw new UnauthorizedError('Invalid or expired SAML session');
  }

  const sessionId = (sessionResult.rows[0] as unknown as IdRow).id;

  // Extract email from assertion
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

  if (!email) {
    throw new UnauthorizedError('SAML assertion missing email');
  }

  // Find or create user
  let isNewUser = false;
  let userResult = await db.execute(
    sql`SELECT id, email, name, created_at FROM users WHERE email = ${email.toLowerCase()}`
  );

  let userId: string;

  if (userResult.rows.length === 0) {
    if (!config.autoProvisionUsers) {
      throw new UnauthorizedError('User not found and auto-provisioning is disabled');
    }

    // Create new user via SSO
    const createResult = await db.execute(
      sql`INSERT INTO users (email, name, email_verified, sso_provider, sso_subject_id)
          VALUES (${email.toLowerCase()}, ${name}, true, 'saml', ${assertion.nameId})
          RETURNING id, email, name, created_at`
    );
    userResult = createResult;
    isNewUser = true;
    userId = (createResult.rows[0] as unknown as UserRow).id;

    // Auto-add to team
    if (config.autoAddToTeam) {
      await db.execute(
        sql`INSERT INTO team_members (team_id, user_id, role)
            VALUES (${config.teamId}, ${userId}, ${config.defaultRole})
            ON CONFLICT DO NOTHING`
      );
    }

    logger.info({ userId, email, teamId: config.teamId }, 'SSO user auto-provisioned');
  } else {
    userId = (userResult.rows[0] as unknown as UserRow).id;

    // Update SSO linkage if not already set
    await db.execute(
      sql`UPDATE users SET sso_provider = 'saml', sso_subject_id = ${assertion.nameId},
              updated_at = NOW()
          WHERE id = ${userId} AND sso_provider IS NULL`
    );
  }

  // Mark session completed
  await db.execute(
    sql`UPDATE sso_sessions SET status = 'completed', user_id = ${userId},
            completed_at = NOW()
        WHERE id = ${sessionId}`
  );

  const userRow = userResult.rows[0] as unknown as UserRow;
  const user: UserData = {
    id: userRow.id,
    email: userRow.email,
    name: userRow.name,
    createdAt: userRow.created_at,
  };

  const tokens = generateTokens(user.id, user.email);

  logger.info({ userId: user.id, teamId: config.teamId, isNewUser }, 'SAML authentication successful');

  return { user, tokens, isNewUser };
}

/**
 * Parse a SAML assertion from response XML.
 * NOTE: In production, use xml-crypto to verify the XML signature against
 * the IdP certificate. This implementation extracts fields without
 * cryptographic verification for the initial implementation.
 */
function parseSAMLAssertion(responseXml: string, config: SSOConfig): SAMLAssertion {
  // Extract key fields using regex (production: use xml2js + xml-crypto)
  function escapeRegExp(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  const getElement = (tag: string): string => {
    const safeTag = escapeRegExp(tag);
    const match = responseXml.match(new RegExp(`<[^>]*:?${safeTag}[^>]*>([^<]+)<`));
    return match ? match[1].trim() : '';
  };

  const getAttr = (tag: string, attr: string): string => {
    const safeTag = escapeRegExp(tag);
    const safeAttr = escapeRegExp(attr);
    const match = responseXml.match(new RegExp(`<[^>]*:?${safeTag}[^>]*${safeAttr}="([^"]+)"`));
    return match ? match[1] : '';
  };

  const nameId = getElement('NameID');
  const issuer = getElement('Issuer');
  const inResponseTo = getAttr('Response', 'InResponseTo') || getAttr('Assertion', 'InResponseTo');

  // Verify issuer matches IdP
  if (issuer && issuer !== config.idpEntityId) {
    throw new UnauthorizedError(`SAML assertion issuer mismatch: expected ${config.idpEntityId}, got ${issuer}`);
  }

  // Extract attributes.
  //
  // responseXml is base64-decoded from an unauthenticated POST to the ACS
  // endpoint, so this regex runs on hostile input. The previous pattern used
  // `<[^>]*:?Attribute` and `[\s\S]*?<[^>]*:?AttributeValue`: `[^>]*` and
  // `[\s\S]*?` can both consume '<', so every '<' in the document was a match
  // start that backtracked across the rest of the document — quadratic time on
  // a body of repeated '<'. Every quantifier below is bounded and its character
  // class excludes the delimiter that follows it, so no position can be matched
  // two different ways and the scan stays linear. The optional namespace prefix
  // ("saml:", "saml2:", "ns2:") is matched explicitly instead of by a wildcard.
  const attributes = new Map<string, string | string[]>();
  const attrRegex =
    /<(?:[A-Za-z0-9_.-]{1,64}:)?Attribute\s+Name="([^"<>]{1,256})"[^<>]{0,1024}>[^<]{0,4096}<(?:[A-Za-z0-9_.-]{1,64}:)?AttributeValue[^<>]{0,1024}>([^<]{1,4096})</g;
  let attrMatch;
  while ((attrMatch = attrRegex.exec(responseXml)) !== null) {
    attributes.set(attrMatch[1], attrMatch[2].trim());
  }

  return {
    nameId,
    nameIdFormat: getAttr('NameID', 'Format'),
    sessionIndex: getAttr('AuthnStatement', 'SessionIndex'),
    attributes,
    issuer,
    inResponseTo,
    notBefore: getAttr('Conditions', 'NotBefore'),
    notOnOrAfter: getAttr('Conditions', 'NotOnOrAfter'),
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
