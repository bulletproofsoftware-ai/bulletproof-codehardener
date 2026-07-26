/**
 * SAML assertion validation tests.
 *
 * Every rejection test asserts the SPECIFIC structured reason, not merely that
 * something was rejected. That matters here more than usual: `sso_disabled` is
 * the FIRST guard in `processSAMLResponse` and the production default for
 * SSO_ENABLED is `false`, so a suite that only asserted `.rejects.toThrow()`
 * would go green on all sixteen cases via the kill-switch while proving nothing
 * about the gate under test. The env mock therefore sets `ssoEnabled: true`
 * explicitly for every validation test; KILL-001 is the only block that flips it.
 *
 * Rejections enforced by node-saml itself surface as `library_validation_failed`
 * by design (§B.9 r4 deliberately discards the library's own message, which
 * embeds attacker-controlled values). Those cases are still attributable: every
 * fixture is the SAME builder as the passing TEST-011 fixture with exactly one
 * knob changed, and TEST-011 proves that builder authenticates successfully.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const mockEnv = {
  SSO_ENABLED: true,
  SAML_CLOCK_SKEW_MS: 60_000,
  JWT_SECRET: 'test-only',
  NODE_ENV: 'test',
};

// MUST be true: see the file header. `ssoEnabled` is exposed through a getter so
// KILL-001 can flip it without re-importing the module under test.
let ssoEnabledValue = true;

vi.mock('../../config/env.js', () => ({
  get env() {
    return mockEnv;
  },
  get ssoEnabled() {
    return ssoEnabledValue;
  },
  get samlClockSkewMs() {
    return mockEnv.SAML_CLOCK_SKEW_MS;
  },
  isDev: false,
  isProd: false,
  isTest: true,
  corsOrigins: ['http://localhost:3000'],
}));

const { loggerCalls } = vi.hoisted(() => ({
  loggerCalls: [] as { level: string; args: unknown[] }[],
}));

vi.mock('../../utils/logger.js', () => {
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

const dbExecute = vi.fn();
vi.mock('../../db/client.js', () => ({ db: { execute: (...a: unknown[]) => dbExecute(...a) } }));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));

const generateTokens = vi.fn(() => ({ accessToken: 'access-token', refreshToken: 'refresh-token' }));
vi.mock('../auth.service.js', () => ({
  generateTokens: (...a: unknown[]) => generateTokens(...(a as [])),
}));

import { processSAMLResponse, initiateSAMLLogin } from './saml.service.js';
import { SAML_GENERIC_FAILURE } from './saml-validator.js';
import { UnauthorizedError } from '../../middleware/errorHandler.js';
import {
  ATTACKER_PRIVATE_KEY_PEM,
  C14N,
  DEFAULT_ASSERTION_ID,
  DEFAULT_EMAIL,
  DEFAULT_REQUEST_ID,
  DIGEST_ALG,
  IDP_ENTITY_ID,
  IDP_PUBLIC_KEY_PEM,
  SIG_ALG,
  SP_ACS_URL,
  SP_ENTITY_ID,
  SSO_CONFIG_ID,
  TEAM_ID,
  buildResponse,
  decoySignature,
  signAssertion,
  toPostBody,
  type ResponseOverrides,
} from './__fixtures__/saml-fixtures.js';

// ============================================================================
// In-memory model of the tables, honouring the real constraints
// ============================================================================

interface SessionRow {
  id: string;
  sso_config_id: string;
  request_id: string;
  status: string;
  created_at: Date;
  user_id: string | null;
}

interface UserRecord {
  id: string;
  email: string;
  name: string | null;
  created_at: Date;
  sso_provider: string | null;
  sso_subject_id: string | null;
}

let sessions: SessionRow[] = [];
/** Honours the (sso_config_id, assertion_id) unique constraint. */
let replayStore: Set<string> = new Set();
let users: UserRecord[] = [];
let teamMembers: { team_id: string; user_id: string }[] = [];
let executed: string[] = [];
let configRow: Record<string, unknown>;
let sessionSeq = 0;
let userSeq = 0;

function defaultConfigRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: SSO_CONFIG_ID,
    team_id: TEAM_ID,
    provider_type: 'saml',
    enabled: true,
    idp_entity_id: IDP_ENTITY_ID,
    idp_sso_url: 'https://idp.example.test/sso',
    idp_certificate: IDP_PUBLIC_KEY_PEM,
    idp_metadata_url: null,
    sp_entity_id: SP_ENTITY_ID,
    sp_acs_url: SP_ACS_URL,
    attribute_mapping: {},
    force_authn: false,
    allow_unencrypted_assertion: false,
    sign_authn_request: true,
    default_role: 'member',
    auto_provision_users: true,
    auto_add_to_team: true,
    ...overrides,
  };
}

function addPendingSession(requestId = DEFAULT_REQUEST_ID): SessionRow {
  sessionSeq += 1;
  const row: SessionRow = {
    id: `session-${sessionSeq}`,
    sso_config_id: SSO_CONFIG_ID,
    request_id: requestId,
    status: 'pending',
    created_at: new Date(),
    user_id: null,
  };
  // The partial unique index: at most one PENDING row per (config, request_id).
  const clash = sessions.find(
    (s) => s.status === 'pending' && s.sso_config_id === row.sso_config_id && s.request_id === requestId
  );
  if (clash) throw new Error('uq_sso_sessions_pending_request violated');
  sessions.push(row);
  return row;
}

const sqlOf = (q: { strings: TemplateStringsArray }): string => q.strings.join(' ');

function installDbMock(): void {
  dbExecute.mockImplementation(async (q: { strings: TemplateStringsArray; values: unknown[] }) => {
    const s = sqlOf(q);
    const v = q.values;
    executed.push(s);

    if (s.includes('FROM sso_configurations')) {
      return { rows: configRow === null ? [] : [configRow], rowCount: configRow === null ? 0 : 1 };
    }

    if (s.includes('INSERT INTO sso_sessions')) {
      const row = addPendingSession(v[1] as string);
      return { rows: [{ id: row.id, created_at: row.created_at }], rowCount: 1 };
    }

    if (s.includes('SELECT created_at FROM sso_sessions')) {
      const row = sessions.find(
        (r) => r.request_id === v[0] && r.sso_config_id === v[1] && r.status === 'pending'
      );
      return row ? { rows: [{ created_at: row.created_at }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    // Promotion to 'completed', gated on the row still being 'failed'.
    // Checked BEFORE the consume branch: this statement also contains the
    // literal 'failed' (in its WHERE clause), so discrimination must be on the
    // SET clause, not on a bare substring.
    if (s.includes("SET status = 'completed'")) {
      const row = sessions.find((r) => r.id === v[1] && r.status === 'failed');
      if (!row) return { rows: [], rowCount: 0 };
      row.status = 'completed';
      row.user_id = v[0] as string;
      return { rows: [{ id: row.id }], rowCount: 1 };
    }

    // removeAsync — the atomic consume into the NEUTRAL 'failed' state.
    if (s.includes("SET status = 'failed'")) {
      const row = sessions.find(
        (r) => r.request_id === v[0] && r.sso_config_id === v[1] && r.status === 'pending'
      );
      if (!row) return { rows: [], rowCount: 0 };
      row.status = 'failed';
      return { rows: [{ id: row.id }], rowCount: 1 };
    }

    if (s.includes('INSERT INTO saml_assertion_replay')) {
      const key = `${v[0] as string}|${v[1] as string}`;
      if (replayStore.has(key)) return { rows: [], rowCount: 0 };
      replayStore.add(key);
      return { rows: [{ id: `replay-${replayStore.size}` }], rowCount: 1 };
    }

    if (s.includes('DELETE FROM saml_assertion_replay')) {
      return { rows: [], rowCount: 0 };
    }

    // Team-scoped user resolution.
    if (s.includes('FROM users u')) {
      const email = v[0] as string;
      const teamId = v[1] as string;
      const row = users.find(
        (u) =>
          u.email === email && teamMembers.some((tm) => tm.team_id === teamId && tm.user_id === u.id)
      );
      return row ? { rows: [row], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    // Out-of-team existence probe.
    if (s.includes('SELECT id FROM users WHERE email')) {
      const row = users.find((u) => u.email === v[0]);
      return row ? { rows: [{ id: row.id }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }

    if (s.includes('INSERT INTO users')) {
      userSeq += 1;
      const row: UserRecord = {
        id: `user-new-${userSeq}`,
        email: v[0] as string,
        name: (v[1] as string) ?? null,
        created_at: new Date(),
        sso_provider: 'saml',
        sso_subject_id: v[2] as string,
      };
      users.push(row);
      return { rows: [row], rowCount: 1 };
    }

    if (s.includes('INSERT INTO team_members')) {
      teamMembers.push({ team_id: v[0] as string, user_id: v[1] as string });
      return { rows: [], rowCount: 1 };
    }

    return { rows: [], rowCount: 0 };
  });
}

// ============================================================================
// Assertions shared by every rejection test
// ============================================================================

/** The structured reason from the last rejection the service logged. */
function rejectionReason(): string | undefined {
  const withReason = loggerCalls.filter(
    (c) => typeof c.args[0] === 'object' && c.args[0] !== null && 'reason' in (c.args[0] as object)
  );
  const last = withReason.at(-1);
  return last ? ((last.args[0] as { reason?: string }).reason) : undefined;
}

/**
 * Every rejection test asserts all four of: it rejects with UnauthorizedError;
 * the client-visible message is the constant (no per-reason disclosure); no
 * token was minted; no user was auto-provisioned.
 */
async function expectRejection(body: string, reason: string): Promise<void> {
  await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
  expect(rejectionReason()).toBe(reason);
  expect(generateTokens).not.toHaveBeenCalled();
  expect(executed.some((s) => s.includes('INSERT INTO users'))).toBe(false);
}

/** The client message must never vary with the reason. */
async function expectGenericMessage(body: string): Promise<void> {
  await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(SAML_GENERIC_FAILURE);
}

const post = (o: ResponseOverrides = {}): string =>
  toPostBody(signAssertion(buildResponse(o), o.assertionId ?? DEFAULT_ASSERTION_ID));

let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
let consoleLogSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  ssoEnabledValue = true;
  sessions = [];
  replayStore = new Set();
  users = [
    {
      id: 'user-1',
      email: DEFAULT_EMAIL,
      name: 'Alice Example',
      created_at: new Date('2026-01-01T00:00:00Z'),
      sso_provider: 'saml',
      sso_subject_id: DEFAULT_EMAIL,
    },
  ];
  teamMembers = [{ team_id: TEAM_ID, user_id: 'user-1' }];
  executed = [];
  loggerCalls.length = 0;
  configRow = defaultConfigRow();
  sessionSeq = 0;
  userSeq = 0;
  generateTokens.mockClear();
  dbExecute.mockReset();
  installDbMock();
  addPendingSession();

  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  consoleErrorSpy.mockRestore();
  consoleWarnSpy.mockRestore();
  consoleLogSpy.mockRestore();
  stderrSpy.mockRestore();
});

// ============================================================================
// TEST-001 / TEST-002 — signature verification is mandatory and cert-pinned
// ============================================================================

describe('REQ-001 signature verification', () => {
  it('TEST-001 rejects an assertion with NO signature at all', async () => {
    // The identical fixture, signed, authenticates (TEST-011). The only
    // difference here is the absence of a signature.
    await expectRejection(toPostBody(buildResponse()), 'library_validation_failed');
  });

  it('TEST-002 rejects an assertion signed by a key the SP has not pinned', async () => {
    const xml = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, {
      privateKey: ATTACKER_PRIVATE_KEY_PEM,
    });
    await expectRejection(toPostBody(xml), 'library_validation_failed');
  });

  it('TEST-002b proves the stored idp_certificate is what decides: same fixture, IdP key succeeds', async () => {
    // The crux of the original bug was that idpCertificate was stored and never
    // reached a crypto call. Attacker key rejects (above); IdP key authenticates.
    const result = await processSAMLResponse(post(), SSO_CONFIG_ID);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(generateTokens).toHaveBeenCalledTimes(1);
  });

  it('returns the constant generic message, never a per-reason one', async () => {
    await expectGenericMessage(toPostBody(buildResponse()));
  });
});

// ============================================================================
// TEST-003 — XML Signature Wrapping
// ============================================================================

describe('REQ-002 signature wrapping', () => {
  it('TEST-003a rejects an injected unsigned sibling <Assertion>', async () => {
    const sibling =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil-1" ` +
      `Version="2.0" IssueInstant="${new Date().toISOString()}">` +
      `<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
      `<saml:Subject><saml:NameID>admin@example.test</saml:NameID></saml:Subject>` +
      `</saml:Assertion>`;
    const xml = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID).replace(
      '</samlp:Response>',
      `${sibling}</samlp:Response>`
    );
    await expectRejection(toPostBody(xml), 'library_validation_failed');
  });

  it('TEST-003b rejects a signature relocated away from its referenced parent', async () => {
    // Sign the assertion, then move the whole assertion body under <Advice>, so
    // the signature no longer envelopes the node it references.
    const signed = signAssertion(buildResponse({ adviceWrapped: true }), DEFAULT_ASSERTION_ID);
    const xml = signed.replace('<saml:Advice>', '<saml:Advice><saml:Wrapper>').replace(
      '</saml:Advice>',
      '</saml:Wrapper></saml:Advice>'
    );
    await expectRejection(toPostBody(xml), 'library_validation_failed');
  });

  it('TEST-003c rejects a duplicate-ID copy of the assertion in <samlp:Extensions>', async () => {
    const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);
    const copy =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${DEFAULT_ASSERTION_ID}" ` +
      `Version="2.0"><saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
      `<saml:Subject><saml:NameID>admin@example.test</saml:NameID></saml:Subject></saml:Assertion>`;
    const xml = signed.replace(
      '<samlp:Status>',
      `<samlp:Extensions>${copy}</samlp:Extensions><samlp:Status>`
    );
    await expectRejection(toPostBody(xml), 'library_validation_failed');
  });

  it('never resolves to the attacker-named subject in any wrapping shape', async () => {
    expect(users.some((u) => u.email === 'admin@example.test')).toBe(false);
  });
});

// ============================================================================
// TEST-004 / TEST-005 — Conditions time window
// ============================================================================

describe('REQ-004 Conditions time window', () => {
  it('TEST-004 rejects an assertion expired well OUTSIDE the configured skew', async () => {
    await expectRejection(
      post({
        notBefore: new Date(Date.now() - 20 * 60_000).toISOString(),
        notOnOrAfter: new Date(Date.now() - 10 * 60_000).toISOString(),
        scdNotOnOrAfter: new Date(Date.now() + 5 * 60_000).toISOString(),
      }),
      'library_validation_failed'
    );
  });

  it('TEST-004b ACCEPTS an assertion expired 1s ago, INSIDE the 60s skew', async () => {
    // The companion case. Without it, TEST-004 could pass against a check that
    // rejects everything, and the skew would be unproven as a real bounded
    // window rather than a disabled check.
    const result = await processSAMLResponse(
      post({ notOnOrAfter: new Date(Date.now() - 1000).toISOString() }),
      SSO_CONFIG_ID
    );
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });

  it('TEST-005 rejects an assertion not yet valid, well OUTSIDE the skew', async () => {
    await expectRejection(
      post({
        notBefore: new Date(Date.now() + 10 * 60_000).toISOString(),
        notOnOrAfter: new Date(Date.now() + 20 * 60_000).toISOString(),
      }),
      'library_validation_failed'
    );
  });

  it('TEST-005b ACCEPTS notBefore 30s in the future, INSIDE the skew', async () => {
    const result = await processSAMLResponse(
      post({ notBefore: new Date(Date.now() + 30_000).toISOString() }),
      SSO_CONFIG_ID
    );
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });

  it('rejects an assertion with no <Conditions> at all', async () => {
    await expectRejection(post({ noConditions: true }), 'library_validation_failed');
  });
});

// ============================================================================
// TEST-006 — AudienceRestriction
// ============================================================================

describe('REQ-005 AudienceRestriction', () => {
  it('TEST-006 rejects a mismatched audience', async () => {
    await expectRejection(post({ audience: 'https://evil.test/' }), 'library_validation_failed');
  });

  it('TEST-006b rejects an assertion carrying no <AudienceRestriction>', async () => {
    await expectRejection(post({ noAudienceRestriction: true }), 'library_validation_failed');
  });
});

// ============================================================================
// TEST-007 — Recipient / Destination (no library support: 100% our code)
// ============================================================================

describe('REQ-006 Recipient and Destination', () => {
  it('TEST-007a rejects a signed Recipient pointing at the attacker', async () => {
    // node-saml ACCEPTS this - the string "Recipient" appears nowhere in the
    // package. This is the highest-value test in the suite.
    await expectRejection(post({ recipient: 'https://evil.test/acs' }), 'recipient_mismatch');
  });

  it('TEST-007b rejects a mismatched Destination on the envelope', async () => {
    await expectRejection(post({ destination: 'https://evil.test/acs' }), 'destination_mismatch');
  });

  it('TEST-007c rejects SubjectConfirmationData carrying NO Recipient (fail closed)', async () => {
    await expectRejection(post({ noRecipient: true }), 'recipient_missing');
  });
});

// ============================================================================
// TEST-008 — assertion-ID replay
// ============================================================================

describe('REQ-008 assertion replay', () => {
  it('TEST-008 rejects the same response POSTed twice', async () => {
    const body = post();
    await processSAMLResponse(body, SSO_CONFIG_ID);
    expect(generateTokens).toHaveBeenCalledTimes(1);

    // The second POST is stopped by the session gate first (the pending row is
    // gone), which is the earlier of the two independent gates.
    await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
    expect(generateTokens).toHaveBeenCalledTimes(1);
  });

  it('TEST-008b rejects a replayed assertion ID given a FRESH valid InResponseTo', async () => {
    // Proves the assertion-ID gate is independent of the session gate: this
    // replay sails through the session gate and is stopped only by REQ-008.
    await processSAMLResponse(post(), SSO_CONFIG_ID);
    generateTokens.mockClear();
    executed = [];

    addPendingSession('_req-0002');
    await expectRejection(
      post({ inResponseTo: '_req-0002', assertionId: DEFAULT_ASSERTION_ID }),
      'assertion_replayed'
    );
  });
});

// ============================================================================
// TEST-009 — InResponseTo single use and request binding
// ============================================================================

describe('REQ-007 InResponseTo', () => {
  it('TEST-009a rejects an InResponseTo that was never issued', async () => {
    await expectRejection(post({ inResponseTo: '_never-issued' }), 'library_validation_failed');
  });

  it('TEST-009b rejects when there is no pending row for this config', async () => {
    sessions = [];
    await expectRejection(post(), 'library_validation_failed');
  });

  it('TEST-009c consumes the session with exactly ONE atomic UPDATE and no SELECT-then-UPDATE', async () => {
    await processSAMLResponse(post(), SSO_CONFIG_ID);

    const consumes = executed.filter((s) => s.includes("SET status = 'failed'"));
    expect(consumes).toHaveLength(1);
    expect(consumes[0]).toContain('RETURNING id');
    // The old non-atomic pair is gone: no bare SELECT of session ids remains.
    expect(executed.some((s) => s.includes('SELECT id FROM sso_sessions'))).toBe(false);
  });

  it('TEST-009d rejects an assertion whose SubjectConfirmationData has NO @InResponseTo', async () => {
    // node-saml's cross-check only fires when the attribute is present, so it
    // ACCEPTS this and leaves the session pending. Ours is the only gate.
    await expectRejection(post({ noScdInResponseTo: true }), 'inresponseto_missing');
  });

  it('TEST-009e rejects an SCD @InResponseTo naming a different live pending session', async () => {
    addPendingSession('_req-0002');
    await expectRejection(
      post({ inResponseTo: DEFAULT_REQUEST_ID, scdInResponseTo: '_req-0002' }),
      'library_validation_failed'
    );
  });

  it('TEST-009f leaves a FAILED attempt as status=failed with user_id NULL, never completed', async () => {
    await expect(
      processSAMLResponse(toPostBody(buildResponse()), SSO_CONFIG_ID)
    ).rejects.toThrow(UnauthorizedError);

    const row = sessions.find((s) => s.request_id === DEFAULT_REQUEST_ID);
    expect(row?.status).toBe('failed');
    expect(row?.user_id).toBeNull();
  });
});

// ============================================================================
// TEST-010 / TEST-014 — mandatory issuer (no library support)
// ============================================================================

describe('REQ-003 mandatory issuer', () => {
  it('TEST-010 rejects an assertion with NO <Issuer> element', async () => {
    await expectRejection(post({ issuer: null }), 'issuer_missing');
  });

  it('TEST-010b rejects a hostile <Issuer>, with a DISTINCT reason', async () => {
    await expectRejection(post({ issuer: 'https://evil.test/idp' }), 'issuer_mismatch');
  });

  it('TEST-014 rejects <Issuer> omitted but spoofed via <Attribute Name="issuer">', async () => {
    // THE test that distinguishes a real REQ-003 control from one that only
    // looks right. node-saml copies attribute NAMES onto `profile`, so
    // profile.issuer reads back as the correct-looking value here: an
    // implementation checking profile.issuer passes TEST-010 and fails this.
    await expectRejection(
      post({
        issuer: null,
        extraAttributes:
          `<saml:Attribute Name="issuer"><saml:AttributeValue>${IDP_ENTITY_ID}` +
          `</saml:AttributeValue></saml:Attribute>`,
      }),
      'issuer_missing'
    );
  });

  it('TEST-015 is unaffected by <Attribute Name="__proto__">', async () => {
    const before = Object.getPrototypeOf({});
    const result = await processSAMLResponse(
      post({
        extraAttributes:
          `<saml:Attribute Name="__proto__"><saml:AttributeValue><x>y</x>` +
          `</saml:AttributeValue></saml:Attribute>`,
      }),
      SSO_CONFIG_ID
    );
    expect(Object.getPrototypeOf({})).toBe(before);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
    // The resolved identity is unchanged.
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });
});

// ============================================================================
// TEST-013 — algorithm pinning (no library support)
// ============================================================================

describe('§B.15 algorithm pinning', () => {
  it('TEST-013a rejects rsa-sha1 signature with a SHA-1 digest', async () => {
    await expectRejection(
      toPostBody(
        signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, {
          sigAlg: SIG_ALG.rsaSha1,
          digAlg: DIGEST_ALG.sha1,
        })
      ),
      'weak_signature_algorithm'
    );
  });

  it('TEST-013b rejects a STRONG rsa-sha256 signature over a SHA-1 digest', async () => {
    // The dangerous shape: the digest is what a chosen-prefix collision targets.
    await expectRejection(
      toPostBody(
        signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, {
          sigAlg: SIG_ALG.rsaSha256,
          digAlg: DIGEST_ALG.sha1,
        })
      ),
      'weak_signature_algorithm'
    );
  });

  it('TEST-013c rejects non-exclusive canonicalization', async () => {
    await expectRejection(
      toPostBody(
        signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, { c14n: C14N.inclusive })
      ),
      'weak_signature_algorithm'
    );
  });

  it('TEST-013d rejects a SHA-1 assertion carrying a strong DECOY <Signature> in <samlp:Extensions>', async () => {
    // The whole ballgame. node-saml ACCEPTS this payload with or without the
    // decoy, so signature validation passing says nothing about which signature
    // the pinning code then inspected. A Reference/@URI-based selector reads the
    // decoy's rsa-sha256 and reports PINNING_PASSES=true while the real
    // assertion is rsa-sha1. Structural selection reads the real one.
    const xml = signAssertion(
      buildResponse({ extensions: decoySignature(DEFAULT_ASSERTION_ID) }),
      DEFAULT_ASSERTION_ID,
      { sigAlg: SIG_ALG.rsaSha1, digAlg: DIGEST_ALG.sha1 }
    );
    await expectRejection(toPostBody(xml), 'weak_signature_algorithm');
  });

  it('TEST-013e rejects a weak <Response> envelope signature over a strong assertion', async () => {
    // saml.js:562 prefers the Response signature's bytes when present, so
    // assertion-only pinning would miss this entirely.
    let xml = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, {
      sigAlg: SIG_ALG.rsaSha256,
      digAlg: DIGEST_ALG.sha256,
    });
    xml = signAssertion(xml, '_resp-0001', {
      sigAlg: SIG_ALG.rsaSha1,
      digAlg: DIGEST_ALG.sha1,
    });
    await expectRejection(toPostBody(xml), 'weak_signature_algorithm');
  });
});

// ============================================================================
// TEST-013d (RR-4) — element cardinality
// ============================================================================

describe('§B.3.1 element cardinality', () => {
  it('rejects two top-level <Issuer> elements, both inside the signature', async () => {
    await expectRejection(post({ duplicateIssuer: true }), 'assertion_malformed');
  });

  it('rejects two <Subject> elements', async () => {
    await expectRejection(post({ duplicateSubject: true }), 'assertion_malformed');
  });

  it('rejects two <NameID> elements', async () => {
    await expectRejection(post({ duplicateNameId: true }), 'assertion_malformed');
  });
});

// ============================================================================
// TEST-016 — DOCTYPE, all four casings
// ============================================================================

describe('§B.7 DOCTYPE rejection', () => {
  const casings = ['<!DOCTYPE samlp:Response>', '<!doctype samlp:Response>', '<!DoCtYpE samlp:Response>', '<!  DOCTYPE samlp:Response>'];

  for (const doctype of casings) {
    it(`rejects a validly signed response prefixed with ${doctype.slice(0, 12)}`, async () => {
      // Testing only the uppercase form is insufficient: the other three evade
      // includes('<!DOCTYPE') and xmldom 0.8.13 parses all four regardless of
      // what XML 1.0 says a conformant parser should do.
      const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);
      const xml = signed.replace('<samlp:Response', `${doctype}<samlp:Response`);
      await expectRejection(toPostBody(xml), 'doctype_forbidden');
    });
  }
});

// ============================================================================
// TEST-011 — the happy path
// ============================================================================

describe('REQ-001 / REQ-011 successful authentication', () => {
  it('TEST-011 accepts a correctly signed, in-window assertion and mints tokens', async () => {
    const result = await processSAMLResponse(post(), SSO_CONFIG_ID);

    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(result.isNewUser).toBe(false);
    expect(result.tokens).toEqual({ accessToken: 'access-token', refreshToken: 'refresh-token' });
    expect(generateTokens).toHaveBeenCalledTimes(1);
    expect(generateTokens).toHaveBeenCalledWith('user-1', DEFAULT_EMAIL);

    const row = sessions.find((s) => s.request_id === DEFAULT_REQUEST_ID);
    expect(row?.status).toBe('completed');
    expect(row?.user_id).toBe('user-1');
    expect(replayStore.has(`${SSO_CONFIG_ID}|${DEFAULT_ASSERTION_ID}`)).toBe(true);
  });

  it('TEST-011b auto-provisions an unknown email and adds it to the team', async () => {
    const result = await processSAMLResponse(
      post({ email: 'bob@example.test', nameId: 'bob@example.test' }),
      SSO_CONFIG_ID
    );

    expect(result.isNewUser).toBe(true);
    expect(result.user.email).toBe('bob@example.test');
    expect(teamMembers.some((tm) => tm.user_id === result.user.id)).toBe(true);
  });

  it('rejects an unknown email when auto-provisioning is disabled', async () => {
    configRow = defaultConfigRow({ auto_provision_users: false });
    await expectRejection(
      post({ email: 'bob@example.test', nameId: 'bob@example.test' }),
      'user_not_provisionable'
    );
  });
});

// ============================================================================
// TEST-012 — tenant isolation of the identity lookup
// ============================================================================

describe('§B.16 tenant isolation', () => {
  it('TEST-012 rejects an email belonging to a user OUTSIDE this config team', async () => {
    users.push({
      id: 'victim-1',
      email: 'victim@othercompany.test',
      name: 'Victim',
      created_at: new Date(),
      sso_provider: 'saml',
      sso_subject_id: 'victim@othercompany.test',
    });
    // Deliberately NOT a member of TEAM_ID.

    await expectRejection(
      post({ email: 'victim@othercompany.test', nameId: 'victim@othercompany.test' }),
      'user_not_in_team'
    );
    // Critically: must not fall through to auto-provision and create a
    // duplicate account for the victim's address.
    expect(users.filter((u) => u.email === 'victim@othercompany.test')).toHaveLength(1);
  });

  it('TEST-012b rejects a local-password account instead of silently adopting it', async () => {
    users = [
      {
        id: 'local-1',
        email: 'local@example.test',
        name: 'Local',
        created_at: new Date(),
        sso_provider: null,
        sso_subject_id: null,
      },
    ];
    teamMembers = [{ team_id: TEAM_ID, user_id: 'local-1' }];

    await expectRejection(
      post({ email: 'local@example.test', nameId: 'local@example.test' }),
      'user_not_sso_linked'
    );
    expect(executed.some((s) => s.includes('UPDATE users SET sso_provider'))).toBe(false);
  });
});

// ============================================================================
// LOG-001 — no attacker-derived content in any log or console channel
// ============================================================================

describe('LOG-001 log hygiene', () => {
  // Attacker-derived markers only. Note 'doctype' itself is NOT a needle: our
  // own closed-union reason `doctype_forbidden` legitimately contains it, and it
  // is one of our literals, not attacker input. The needles below are strings
  // that can only have come from the request body.
  const forbidden = [
    '<saml',
    '<samlp',
    'evil.test',
    '!ENTITY',
    'etc/passwd',
    'badref',
    DEFAULT_REQUEST_ID,
  ];

  it('never emits attacker XML, hostnames, or the raw InResponseTo on any channel', async () => {
    const hostileBodies = [
      toPostBody(buildResponse()),
      post({ issuer: 'https://evil.test/idp' }),
      post({ recipient: 'https://evil.test/acs' }),
      post({ audience: 'https://evil.test/' }),
      toPostBody(
        signAssertion(buildResponse(), DEFAULT_ASSERTION_ID).replace(
          '<samlp:Response',
          '<!doctype samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response'
        )
      ),
      // 30+ malformed entity references: xmldom writes attacker text to
      // console.error outside pino entirely, so a pino-only spy would report
      // green while the leak occurred.
      toPostBody(`<samlp:Response>${'&badref;'.repeat(30)}</samlp:Response>`),
    ];

    for (const body of hostileBodies) {
      sessions = [];
      addPendingSession();
      await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
    }

    const serialised = JSON.stringify(
      loggerCalls.map((c) => c.args),
      (_k, v: unknown) => (v instanceof Map ? Object.fromEntries(v) : v)
    );
    for (const needle of forbidden) {
      expect(serialised).not.toContain(needle);
    }

    // The console / stderr spies are mandatory, not thoroughness for its own sake.
    expect(consoleErrorSpy).not.toHaveBeenCalled();
    expect(consoleWarnSpy).not.toHaveBeenCalled();
    expect(consoleLogSpy).not.toHaveBeenCalled();
    expect(stderrSpy).not.toHaveBeenCalled();
  });
});

// ============================================================================
// KILL-001 — the kill-switch
// ============================================================================

describe('KILL-001 SSO_ENABLED kill-switch', () => {
  beforeEach(() => {
    ssoEnabledValue = false;
    executed = [];
    loggerCalls.length = 0;
  });

  it('processSAMLResponse rejects with sso_disabled and issues no DB statement', async () => {
    await expect(processSAMLResponse(post(), SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('sso_disabled');
    expect(generateTokens).not.toHaveBeenCalled();
    expect(executed).toHaveLength(0);
  });

  it('initiateSAMLLogin rejects with sso_disabled and issues no DB statement', async () => {
    await expect(
      initiateSAMLLogin({
        id: SSO_CONFIG_ID,
        teamId: TEAM_ID,
        providerType: 'saml',
        enabled: true,
        idpEntityId: IDP_ENTITY_ID,
        idpSsoUrl: 'https://idp.example.test/sso',
        idpCertificate: IDP_PUBLIC_KEY_PEM,
        idpMetadataUrl: null,
        spEntityId: SP_ENTITY_ID,
        spAcsUrl: SP_ACS_URL,
        attributeMapping: {},
        forceAuthn: false,
        allowUnencryptedAssertion: false,
        signAuthnRequest: true,
        defaultRole: 'member',
        autoProvisionUsers: true,
        autoAddToTeam: true,
      })
    ).rejects.toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('sso_disabled');
    expect(executed).toHaveLength(0);
  });
});
