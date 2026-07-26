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

import { processSAMLResponse, initiateSAMLLogin, type SSOConfig } from './saml.service.js';
import {
  SAML_GENERIC_FAILURE,
  SAML_MAX_RESPONSE_BYTES,
  checkConditionsWindow,
  checkSubjectInResponseTo,
  parseResponseDom,
  pinAlgorithms,
  readVerifiedAssertion,
  type SamlLogContext,
  type VerifiedAssertion,
} from './saml-validator.js';
import { SsoSessionCacheProvider } from './sso-session-cache.js';
import { UnauthorizedError } from '../../middleware/errorHandler.js';
import { SAML, ValidateInResponseTo, type Profile } from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import {
  ATTACKER_PRIVATE_KEY_PEM,
  C14N,
  DEFAULT_ASSERTION_ID,
  DEFAULT_EMAIL,
  DEFAULT_REQUEST_ID,
  DIGEST_ALG,
  DOCTYPE_CASINGS,
  IDP_ENTITY_ID,
  IDP_PUBLIC_KEY_PEM,
  SIG_ALG,
  SP_ACS_URL,
  SP_ENTITY_ID,
  SSO_CONFIG_ID,
  TEAM_ID,
  buildResponse,
  decoySignature,
  malformedEntityBody,
  signAssertion,
  signEnvelope,
  toPostBody,
  withAlgorithmDecoyInSignature,
  withDoctype,
  withUnquotedAttributes,
  xswAdviceNested,
  xswDoubleSignature,
  xswDuplicateIdInExtensions,
  xswRelocatedSignature,
  xswSiblingAssertion,
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
  /**
   * node-saml's CacheProvider interface is `saveAsync(key, value)` — two
   * strings, with no room for these. They travel on the provider's constructor
   * instead (§B.8.2), and they are modelled here so REQ-011 can assert the SSO
   * audit trail actually survived the move behind that interface rather than
   * being silently dropped.
   */
  relay_state: string | null;
  ip_address: string | null;
  user_agent: string | null;
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
let configRow: Record<string, unknown> | null;
let sessionSeq = 0;
let userSeq = 0;
/**
 * Forces the atomic consume to match zero rows, modelling the outcome the
 * `WHERE status='pending'` predicate produces for the LOSER of two concurrent
 * POSTs. That branch is the compensation for node-saml's documented TOCTOU and
 * had no test at all (adversarial H-6).
 */
let consumeMatchesZeroRows = false;
/** Forces `INSERT INTO users` to raise, modelling a unique violation (NEW-3). */
let userInsertThrows = false;
/** Forces the promotion UPDATE to match zero rows (NEW-3 / L-1). */
let promotionMatchesZeroRows = false;

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
    relay_state: null,
    ip_address: null,
    user_agent: null,
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
      // REQ-011: all three audit columns must still be written.
      row.relay_state = (v[2] as string | null) ?? null;
      row.ip_address = (v[3] as string | null) ?? null;
      row.user_agent = (v[4] as string | null) ?? null;
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
      if (promotionMatchesZeroRows) return { rows: [], rowCount: 0 };
      const row = sessions.find((r) => r.id === v[1] && r.status === 'failed');
      if (!row) return { rows: [], rowCount: 0 };
      row.status = 'completed';
      row.user_id = v[0] as string;
      return { rows: [{ id: row.id }], rowCount: 1 };
    }

    // removeAsync — the atomic consume into the NEUTRAL 'failed' state.
    if (s.includes("SET status = 'failed'")) {
      if (consumeMatchesZeroRows) return { rows: [], rowCount: 0 };
      const row = sessions.find(
        (r) => r.request_id === v[0] && r.sso_config_id === v[1] && r.status === 'pending'
      );
      if (!row) return { rows: [], rowCount: 0 };
      row.status = 'failed';
      // `relay_state` rides back on the SAME atomic statement (H-7): the ACS
      // route may only compare the posted RelayState against this value.
      return { rows: [{ id: row.id, relay_state: row.relay_state }], rowCount: 1 };
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
      if (userInsertThrows) {
        throw new Error(
          'duplicate key value violates unique constraint "users_email_key" DETAIL: Key (email)=(bob@example.test) already exists.'
        );
      }
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

/** The structured `reason` of a single recorded log call, if it carries one. */
function rejectionReasonOf(call: { args: unknown[] }): string | undefined {
  const first = call.args[0];
  if (typeof first !== 'object' || first === null || !('reason' in first)) return undefined;
  return (first as { reason?: string }).reason;
}

/** The structured reason from the last rejection the service logged. */
function rejectionReason(): string | undefined {
  const withReason = loggerCalls.filter((c) => rejectionReasonOf(c) !== undefined);
  const last = withReason.at(-1);
  return last ? rejectionReasonOf(last) : undefined;
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
  consumeMatchesZeroRows = false;
  userInsertThrows = false;
  promotionMatchesZeroRows = false;
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

  it('TEST-001b rejects a response signed ONLY at the <Response> envelope, assertion unsigned', async () => {
    // QA GAP-4. `wantAssertionsSigned: true -> false` broke NO test, and QA
    // proved by probing node-saml 5.1.0 directly that the mutation is NOT
    // equivalent: this exact shape is REJECTED with the flag true and ACCEPTED
    // with it false. It is the one shape the flag is load-bearing for, and
    // nothing in the suite signed the envelope alone — TEST-013e signs both.
    //
    // The specific reason matters: with the flag flipped, node-saml accepts and
    // the request instead dies at `pinAlgorithms` (no <Signature> that is a
    // direct child of the <Assertion>) with `weak_signature_algorithm`, so
    // asserting the exact reason is what turns this red.
    const xml = signEnvelope(buildResponse());
    expect(xml).toContain('<Signature');
    await expectRejection(toPostBody(xml), 'library_validation_failed');
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
    // Relocate the INTACT signature to be a direct child of <Response> while its
    // Reference/@URI still names the assertion. The signed byte range is
    // untouched, so this is a genuine relocation rather than tampering that any
    // digest check would catch — it is specifically the enveloped-only guard
    // (xml.js:93) that must fire. Asserted by message below.
    await expectRejection(toPostBody(xswRelocatedSignature()), 'library_validation_failed');
  });

  it('TEST-003d rejects the genuinely signed assertion buried in <saml:Advice>', async () => {
    // An unsigned attacker assertion sits at the normal position; the real signed
    // one is nested inside its <Advice>. node-saml only searches direct children
    // of assertions[0], so the real signature is never found.
    const xml = xswAdviceNested();
    expect(xml).toContain('admin@example.test');
    await expectRejection(toPostBody(xml), 'library_validation_failed');
  });

  it('TEST-003e rejects an assertion carrying two signatures', async () => {
    await expectRejection(toPostBody(xswDoubleSignature()), 'library_validation_failed');
  });

  /**
   * The service deliberately discards node-saml's error text (§B.9 r4), so all
   * five shapes are indistinguishable through `processSAMLResponse` — which is
   * the required behaviour, but it means the tests above cannot show that FIVE
   * different guards are doing the work rather than one. §B.3 requires the
   * guards be asserted individually so a regression in any single one is caught,
   * so that is done here, directly against the library.
   */
  describe('the five wrapping shapes trip FIVE distinct node-saml guards', () => {
    const rawValidate = async (xml: string): Promise<string> => {
      const store = new Map<string, string>([[DEFAULT_REQUEST_ID, new Date().toISOString()]]);
      const saml = new SAML({
        callbackUrl: SP_ACS_URL,
        issuer: SP_ENTITY_ID,
        idpCert: IDP_PUBLIC_KEY_PEM,
        idpIssuer: IDP_ENTITY_ID,
        audience: SP_ENTITY_ID,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: false,
        validateInResponseTo: ValidateInResponseTo.always,
        requestIdExpirationPeriodMs: 600_000,
        acceptedClockSkewMs: 60_000,
        cacheProvider: {
          saveAsync: async (k: string, val: string) => {
            store.set(k, val);
            return { value: val, createdAt: Date.now() };
          },
          getAsync: async (k: string) => store.get(k) ?? null,
          removeAsync: async (k: string | null) => (k !== null && store.delete(k) ? k : null),
        } as never,
      });
      try {
        await saml.validatePostResponseAsync({ SAMLResponse: toPostBody(xml) });
        return 'ACCEPTED';
      } catch (error) {
        return (error as Error).message;
      }
    };

    it('the baseline fixture is ACCEPTED, so these guards are not rejecting everything', async () => {
      expect(await rawValidate(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID))).toBe(
        'ACCEPTED'
      );
    });

    it('(a) sibling assertion -> multiple-assertions guard', async () => {
      expect(await rawValidate(xswSiblingAssertion())).toContain('multiple assertions');
    });

    it('(b) relocated signature -> enveloped-only guard', async () => {
      expect(await rawValidate(xswRelocatedSignature())).toContain(
        "Referenced node does not refer to it's parent element"
      );
    });

    it('(c) duplicate ID -> ID-resolution guard', async () => {
      expect(await rawValidate(xswDuplicateIdInExtensions())).toContain(
        'ID cannot refer to more than one element'
      );
    });

    it('(e) two signatures -> signature-count guard', async () => {
      expect(await rawValidate(xswDoubleSignature())).toContain('Too many signatures');
    });
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
    // H-4. This assertion is the only one in the file phrased as the ATTACK
    // OUTCOME rather than as a rejection reason, and it used to run no code at
    // all: `users` is reassigned in the top-level `beforeEach`, so it asserted
    // that freshly-initialised state lacked a value nothing had ever written.
    // It passed identically against an implementation in which all five wrapping
    // shapes authenticate `admin@example.test`. The shapes are now actually
    // POSTed before the outcome is checked.
    // `carriesAttacker` records which shapes actually plant
    // `admin@example.test` in the document. Asserting containment on the two
    // that do not would be a false claim; asserting it on the three that do is
    // what stops this test going vacuous if a fixture stops injecting it.
    const shapes: { label: string; xml: string; carriesAttacker: boolean }[] = [
      { label: 'sibling assertion', xml: xswSiblingAssertion(), carriesAttacker: true },
      { label: 'relocated signature', xml: xswRelocatedSignature(), carriesAttacker: false },
      { label: 'duplicate ID in Extensions', xml: xswDuplicateIdInExtensions(), carriesAttacker: true },
      { label: 'advice-nested', xml: xswAdviceNested(), carriesAttacker: true },
      { label: 'double signature', xml: xswDoubleSignature(), carriesAttacker: false },
    ];
    expect(shapes.filter((s) => s.carriesAttacker)).toHaveLength(3);

    for (const { label, xml, carriesAttacker } of shapes) {
      if (carriesAttacker) expect(xml, label).toContain('admin@example.test');
      sessions = [];
      addPendingSession();
      await expect(processSAMLResponse(toPostBody(xml), SSO_CONFIG_ID), label).rejects.toThrow(
        UnauthorizedError
      );
    }

    expect(users.some((u) => u.email === 'admin@example.test')).toBe(false);
    expect(generateTokens).not.toHaveBeenCalled();
    expect(replayStore.size).toBe(0);
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

  // ==========================================================================
  // H-2 / QA GAP-2 — <Conditions> present but not carrying a real time window
  // ==========================================================================

  it('H-2 rejects <Conditions> with ZERO attributes, which node-saml ACCEPTS', async () => {
    // THE bypass. `saml.js:842` is `if (conditions && conditions.$)`, and xml2js
    // only emits `$` for an element that has attributes — so a bare
    // `<Conditions>` skips node-saml's ENTIRE timestamp block while the audience
    // check, which sits outside that guard, still passes. Executed against
    // node-saml alone: an assertion with `IssueInstant` backdated one year and
    // this shape AUTHENTICATES. Anyone holding a valid signature could replay it
    // forever, so REQ-004 was not delivered.
    await expectRejection(post({ noConditionsAttributes: true }), 'conditions_incomplete');
  });

  it('H-2 rejects <Conditions> carrying only NotOnOrAfter — no lower bound is still no window', async () => {
    // Also accepted by node-saml on its own (executed): it validates whichever
    // of the two attributes are present and does not require both.
    await expectRejection(post({ noConditionsNotBefore: true }), 'conditions_incomplete');
  });

  it('H-2 rejects <Conditions> carrying only NotBefore', async () => {
    // node-saml happens to reject this one first ("Error parsing NotOnOrAfter"),
    // so end to end it surfaces as the library reason. The direct unit tests
    // below are what prove OUR guard fires — the guard exists precisely so the
    // guarantee survives a library refactor.
    await expectRejection(post({ noConditionsNotOnOrAfter: true }), 'library_validation_failed');
  });

  /**
   * QA GAP-2: `conditions_missing` appeared in NO test of any kind, and the
   * shapes above are partly masked by node-saml. `readVerifiedAssertion` and
   * `checkConditionsWindow` are therefore exercised directly, on the same xml2js
   * object shape `profile.getAssertion()` returns.
   */
  describe('§B.3.1 <Conditions> guards (direct)', () => {
    const ctx = (): SamlLogContext => ({
      ssoConfigId: SSO_CONFIG_ID,
      teamId: TEAM_ID,
      correlation: 'none',
    });

    /** The xml2js shape of a minimal, otherwise-valid assertion. */
    const assertionWith = (conditions: unknown): Profile =>
      ({
        getAssertion: () => ({
          Assertion: {
            $: { ID: DEFAULT_ASSERTION_ID },
            Issuer: [{ _: IDP_ENTITY_ID }],
            Subject: [
              {
                NameID: [{ _: DEFAULT_EMAIL }],
                SubjectConfirmation: [
                  { SubjectConfirmationData: [{ $: { Recipient: SP_ACS_URL } }] },
                ],
              },
            ],
            ...(conditions === undefined ? {} : { Conditions: conditions }),
          },
        }),
      }) as unknown as Profile;

    const win = (notBefore: string, notOnOrAfter: string): VerifiedAssertion =>
      ({ conditionsNotBefore: notBefore, conditionsNotOnOrAfter: notOnOrAfter }) as VerifiedAssertion;

    it('the baseline shape is READABLE, so the rejections below are about <Conditions>', () => {
      const ok = readVerifiedAssertion(
        assertionWith([{ $: { NotBefore: '2026-01-01T00:00:00Z', NotOnOrAfter: '2030-01-01T00:00:00Z' } }]),
        ctx()
      );
      expect(ok.conditionsNotBefore).toBe('2026-01-01T00:00:00Z');
      expect(ok.conditionsNotOnOrAfter).toBe('2030-01-01T00:00:00Z');
    });

    it('rejects an ABSENT <Conditions> with conditions_missing', () => {
      expect(() => readVerifiedAssertion(assertionWith(undefined), ctx())).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_missing');
    });

    it('rejects <Conditions> with ZERO attributes (no xml2js `$` key)', () => {
      expect(() => readVerifiedAssertion(assertionWith([{}]), ctx())).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_incomplete');
    });

    it('rejects <Conditions> carrying only NotBefore', () => {
      expect(() =>
        readVerifiedAssertion(assertionWith([{ $: { NotBefore: '2026-01-01T00:00:00Z' } }]), ctx())
      ).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_incomplete');
    });

    it('rejects <Conditions> carrying only NotOnOrAfter', () => {
      expect(() =>
        readVerifiedAssertion(assertionWith([{ $: { NotOnOrAfter: '2030-01-01T00:00:00Z' } }]), ctx())
      ).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_incomplete');
    });

    it('checkConditionsWindow rejects an expired window, OUTSIDE the 60s skew', () => {
      expect(() =>
        checkConditionsWindow(
          win(new Date(Date.now() - 20 * 60_000).toISOString(), new Date(Date.now() - 10 * 60_000).toISOString()),
          ctx()
        )
      ).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_expired');
    });

    it('checkConditionsWindow rejects a not-yet-valid window, OUTSIDE the skew', () => {
      expect(() =>
        checkConditionsWindow(
          win(new Date(Date.now() + 10 * 60_000).toISOString(), new Date(Date.now() + 20 * 60_000).toISOString()),
          ctx()
        )
      ).toThrow(UnauthorizedError);
      expect(rejectionReason()).toBe('conditions_not_yet_valid');
    });

    it('checkConditionsWindow ACCEPTS inside the skew at BOTH edges', () => {
      // Without these the two rejections above would also pass against a check
      // that rejects everything, and SAML_CLOCK_SKEW_MS would be unproven as a
      // real bounded window rather than a disabled one.
      expect(() =>
        checkConditionsWindow(
          win(new Date(Date.now() + 30_000).toISOString(), new Date(Date.now() + 300_000).toISOString()),
          ctx()
        )
      ).not.toThrow();
      expect(() =>
        checkConditionsWindow(
          win(new Date(Date.now() - 300_000).toISOString(), new Date(Date.now() - 1_000).toISOString()),
          ctx()
        )
      ).not.toThrow();
    });

    it('checkConditionsWindow rejects unparseable timestamps rather than passing them', () => {
      // `Number.isNaN(...) ? accept : compare` is exactly how H-2 would reopen.
      expect(() => checkConditionsWindow(win('not-a-date', 'not-a-date'), ctx())).toThrow(
        UnauthorizedError
      );
      expect(rejectionReason()).toBe('conditions_incomplete');
    });
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

  it('TEST-007d requires EVERY Recipient to match, not merely one of them', async () => {
    // QA GAP-3. §B.7 states "EVERY `Recipient` present must match, not merely
    // one of them", but no fixture emitted more than one
    // <SubjectConfirmationData>, so inverting `.some(r => r !== url)` to
    // `.every(...)` — turning all-match into any-match, the semantics the spec
    // explicitly forbids — broke no test. The twin control
    // `checkSubjectInResponseTo` already had this case; Recipient did not.
    //
    // One valid Recipient, one pointing elsewhere. Under `.every` the valid one
    // satisfies the check and the assertion authenticates.
    await expectRejection(
      post({ secondRecipient: 'https://evil.test/acs' }),
      'recipient_mismatch'
    );
  });

  it('TEST-007e ACCEPTS two SubjectConfirmationData that BOTH carry the right Recipient', async () => {
    // The companion: proves TEST-007d fails on the mismatch and not merely on
    // the presence of a second confirmation.
    const result = await processSAMLResponse(post({ secondRecipient: SP_ACS_URL }), SSO_CONFIG_ID);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
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
    // gone), which is the earlier of the two independent gates. Asserting the
    // specific reason matters even here: without it this test cannot tell a
    // working replay gate from any other rejection path.
    await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('library_validation_failed');
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

  it('TEST-013f rejects an rsa-sha1 SIGNATURE over a SHA-256 digest (isolates ALLOWED_SIGNATURE_ALGORITHMS)', async () => {
    // QA GAP-1. TEST-013a bundles rsa-sha1 with a SHA-1 digest, so the DIGEST
    // pin kills it and `ALLOWED_SIGNATURE_ALGORITHMS` is never the thing under
    // test — permitting rsa-sha1, or deleting the SignatureMethod check
    // outright, broke no test. This is the shape that isolates it, and unlike
    // every other pin it has no redundant layer: if this allowlist regressed,
    // nothing else in the pipeline would reject an rsa-sha1 signature over a
    // strong digest.
    await expectRejection(
      toPostBody(
        signAssertion(buildResponse(), DEFAULT_ASSERTION_ID, {
          sigAlg: SIG_ALG.rsaSha1,
          digAlg: DIGEST_ALG.sha256,
        })
      ),
      'weak_signature_algorithm'
    );
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
// H-1 — the pin must describe the algorithms xml-crypto ACTUALLY used
// ============================================================================

describe('§B.15 / H-1 the pin and the verifier must select the same node', () => {
  /**
   * These run `pinAlgorithms` DIRECTLY rather than through
   * `processSAMLResponse`, and that is deliberate, not a shortcut.
   *
   * The divergence is only exploitable in combination with a SHA-1 chosen-prefix
   * collision (SHAmbles, ~$45k of GPU): the attacker needs a second `SignedInfo`
   * that collides with the genuine one. Without the collision, xml-crypto
   * verifies with the DECOY's algorithm and the signature simply fails — so an
   * end-to-end fixture can only ever show `library_validation_failed`, which
   * proves nothing about the pin. Calling the pin directly is what shows the
   * control itself firing, and it is the only honest way to test this without
   * computing a collision.
   */
  const ctx = (): SamlLogContext => ({
    ssoConfigId: SSO_CONFIG_ID,
    teamId: TEAM_ID,
    correlation: 'none',
  });
  const domOf = (xml: string): Document => parseResponseDom(xml, ctx());

  it('a clean signed response passes the pin (so the rejections below mean something)', () => {
    expect(() =>
      pinAlgorithms(domOf(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID)), ctx())
    ).not.toThrow();
  });

  it('rejects a foreign-namespace <SignatureMethod> decoy planted before <ds:SignedInfo>', () => {
    // xml-crypto resolves the algorithm it VERIFIES WITH via
    // `.//*[local-name(.)='SignatureMethod']/@Algorithm` — descendant of the
    // whole signature, namespace-agnostic, document order (signed-xml.js:469).
    // The decoy sits OUTSIDE <SignedInfo>, so `SignatureValue` does not cover it
    // and the enveloped-signature transform strips it from the digest: it is
    // free for an attacker to add to a genuinely signed response. The old pin
    // read ds:SignedInfo/ds:SignatureMethod and reported rsa-sha256 while
    // xml-crypto would have verified with rsa-sha1.
    const xml = withAlgorithmDecoyInSignature(
      signAssertion(buildResponse(), DEFAULT_ASSERTION_ID),
      'SignatureMethod',
      SIG_ALG.rsaSha1
    );
    expect(xml).toContain('urn:decoy:test');
    expect(() => pinAlgorithms(domOf(xml), ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('signature_algorithm_divergence');
  });

  it('rejects a foreign-namespace <CanonicalizationMethod> decoy planted before <ds:SignedInfo>', () => {
    const xml = withAlgorithmDecoyInSignature(
      signAssertion(buildResponse(), DEFAULT_ASSERTION_ID),
      'CanonicalizationMethod',
      C14N.inclusive
    );
    expect(() => pinAlgorithms(domOf(xml), ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('signature_algorithm_divergence');
  });

  it('rejects even a decoy that names a STRONG algorithm — divergence itself is the defect', () => {
    // Not "is the value acceptable" but "is there more than one candidate". A
    // pin that only rejected weak decoys would still be reading a different node
    // from the one that ran.
    const xml = withAlgorithmDecoyInSignature(
      signAssertion(buildResponse(), DEFAULT_ASSERTION_ID),
      'SignatureMethod',
      SIG_ALG.rsaSha512
    );
    expect(() => pinAlgorithms(domOf(xml), ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('signature_algorithm_divergence');
  });

  it('NEW-2 rejects a <Reference> carrying NO <Transforms> instead of skipping the allowlist', () => {
    // The old loop was `for (const t of elementChildren(reference,'Transforms',DS_NS))`:
    // zero matches meant the body never ran and the transform allowlist was
    // silently SKIPPED — "absence => pass", the exact shape §B.4 forbids.
    const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);
    const xml = signed.replace(/<Transforms>[\s\S]*?<\/Transforms>/, '');
    expect(xml).not.toContain('<Transforms>');
    expect(() => pinAlgorithms(domOf(xml), ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('weak_signature_algorithm');
  });

  it('NEW-2 rejects a foreign-namespace <Transforms> wrapper, which xml-crypto WOULD honour', () => {
    // `utils.findChildren(refNode,'Transforms')` passes no namespace and
    // `utils.js:34` treats null as "match any", so xml-crypto honours a
    // <Transforms> in ANY namespace while our ds-qualified read saw none.
    const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);
    const xml = signed
      .replace('<Transforms>', '<x:Transforms xmlns:x="urn:decoy:test">')
      .replace('</Transforms>', '</x:Transforms>');
    expect(() => pinAlgorithms(domOf(xml), ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('weak_signature_algorithm');
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

  it('TEST-011c returns the SP-STORED relay state from the atomic consume (H-7)', async () => {
    // The ACS route may only compare the posted RelayState against this value,
    // never redirect to the posted one — so the value has to travel back out of
    // the same single statement that consumed the row, and it has to be the
    // row's, not the request body's.
    sessions = [];
    const pending = addPendingSession();
    pending.relay_state = 'https://app.example.test/dashboard';

    const result = await processSAMLResponse(post(), SSO_CONFIG_ID);
    expect(result.relayState).toBe('https://app.example.test/dashboard');
  });

  it('TEST-011d returns a null relay state when the SP stored none', async () => {
    const result = await processSAMLResponse(post(), SSO_CONFIG_ID);
    expect(result.relayState).toBeNull();
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
    // The deleted behaviour was an UPDATE performed by an unauthenticated POST.
    // Assert on ANY write to users, not just the old statement's exact text —
    // matching the removed wording alone would be a tautology that stays green
    // no matter what replaces it.
    expect(executed.some((s) => s.includes('UPDATE users'))).toBe(false);
    expect(users[0].sso_provider).toBeNull();
    expect(users[0].sso_subject_id).toBeNull();
  });

  it('TEST-012c rejects an SSO account whose subject id is bound to a different subject', async () => {
    users = [
      {
        id: 'sso-1',
        email: DEFAULT_EMAIL,
        name: 'Alice Example',
        created_at: new Date(),
        sso_provider: 'saml',
        sso_subject_id: 'someone-else@example.test',
      },
    ];
    teamMembers = [{ team_id: TEAM_ID, user_id: 'sso-1' }];

    await expectRejection(post(), 'user_not_sso_linked');
    expect(executed.some((s) => s.includes('UPDATE users'))).toBe(false);
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
    'ATTACKERMARKER',
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
      // NEW-1. Every payload above is ERROR-class to xmldom, and node-saml's
      // strict parse rejects all of those BEFORE xml-crypto is reached — which
      // is why this suite was green while the channel was open. An unquoted
      // attribute value is a xmldom *WARNING*, so before the fix this document
      // survived node-saml, reached xml-crypto's unconfigured DOMParser inside
      // `checkSignature`, AUTHENTICATED SUCCESSFULLY, and wrote
      // `[xmldom warning] attribute "ATTACKERMARKER0" missed quot(")!` to
      // stderr — outside pino, outside every redaction rule in this module.
      toPostBody(withUnquotedAttributes(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID), 1)),
      // And it amplified 1:1 with the attacker's chosen count (executed:
      // 1 / 50 / 400 attributes -> 1 / 50 / 400 stderr writes), bounded only by
      // the 1 MiB body cap, on an unauthenticated endpoint.
      toPostBody(withUnquotedAttributes(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID), 50)),
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
// Input screening — the rejection reasons reachable before any parsing
// ============================================================================

describe('input screening (§B.3.3, §B.9)', () => {
  it('rejects a missing body', async () => {
    await expectRejection('', 'response_missing');
    await expect(
      processSAMLResponse(undefined as unknown as string, SSO_CONFIG_ID)
    ).rejects.toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('response_missing');
  });

  it('rejects an oversized body BEFORE decoding or parsing it', async () => {
    // Bounds XML-parser CPU and memory on unauthenticated input.
    await expectRejection('A'.repeat(SAML_MAX_RESPONSE_BYTES + 1), 'response_too_large');
    expect(executed.some((s) => s.includes('sso_sessions'))).toBe(false);
  });

  it('rejects an unknown SSO configuration', async () => {
    configRow = null;
    await expectRejection(post(), 'config_missing');
  });

  it('rejects a per-team disabled configuration', async () => {
    configRow = defaultConfigRow({ enabled: false });
    await expectRejection(post(), 'config_disabled');
  });

  it('rejects a body that is not XML at all', async () => {
    // Reason TIGHTENED, not relaxed. The well-formedness screen (NEW-1) now runs
    // BEFORE node-saml, so this is caught by our own root-element check rather
    // than delegated to the library. `response_root_invalid` is a strictly more
    // specific assertion than `library_validation_failed`: it names OUR gate,
    // and it fails if the screen is ever moved back behind node-saml.
    await expectRejection(toPostBody('not xml at all'), 'response_root_invalid');
  });

  it('routes an unusable idp_certificate through the sanitized path (MED-7)', async () => {
    // The SAML constructor throws for an absent trust anchor, and in dev
    // errorHandler echoes err.message for non-AppError throws — so the
    // constructor has to sit inside the guarded path rather than outside it.
    configRow = defaultConfigRow({ idp_certificate: '' });
    await expectRejection(post(), 'idp_cert_unusable');
  });

  it('a malformed-but-present certificate fails closed at validation, not at construction', async () => {
    // Measured, not assumed: node-saml's constructor only rejects an ABSENT
    // idpCert ("idpCert is required"). Certificate CONTENT is not parsed until
    // signature verification, so this lands as library_validation_failed rather
    // than idp_cert_unusable. Both are rejections and both are sanitized; the
    // distinction is recorded so the reason codes are not misread as a
    // certificate-shape validator that does not exist.
    configRow = defaultConfigRow({ idp_certificate: 'not-a-certificate' });
    await expectRejection(post(), 'library_validation_failed');
  });
});

// ============================================================================
// §B.7 — Destination is advisory, and its ABSENCE is deliberately allowed
// ============================================================================

describe('§B.7 Destination absence asymmetry', () => {
  it('accepts an absent Destination while still requiring Recipient', async () => {
    // Deliberate asymmetry: Destination is optional per SAML 2.0 Core on an
    // unsigned envelope, so absent is allowed and present-and-wrong rejects.
    // It looks like the REQ-003 fail-open bug and is not one — the authoritative
    // binding check is Recipient, which is inside the signature and mandatory
    // (proved by TEST-007c).
    const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);
    const xml = signed.replace(` Destination="${SP_ACS_URL}"`, '');
    expect(xml).not.toContain('Destination=');

    const result = await processSAMLResponse(toPostBody(xml), SSO_CONFIG_ID);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });
});

// ============================================================================
// §B.8.5 — the request-binding branch the library masks
// ============================================================================

describe('§B.8.5 request binding (direct)', () => {
  /**
   * End to end, an SCD @InResponseTo naming a different session is caught by
   * node-saml's own cross-check first (TEST-009e), so our defence-in-depth
   * branch never runs there. §B.8.1 exists precisely because that library check
   * is not reachable on every path, so the branch is exercised directly rather
   * than left as untested code.
   */
  const ctx = (): SamlLogContext => ({
    ssoConfigId: SSO_CONFIG_ID,
    teamId: TEAM_ID,
    correlation: 'none',
  });
  const withIrt = (values: string[]): VerifiedAssertion =>
    ({ subjectInResponseTo: values }) as VerifiedAssertion;

  it('accepts only the request id the flow actually consumed', () => {
    expect(() => checkSubjectInResponseTo(withIrt(['_req-0001']), '_req-0001', ctx())).not.toThrow();
  });

  it('rejects a value that is not the consumed id, with inresponseto_mismatch', () => {
    expect(() => checkSubjectInResponseTo(withIrt(['_req-0001']), '_other-live', ctx())).toThrow(
      UnauthorizedError
    );
    expect(rejectionReason()).toBe('inresponseto_mismatch');
  });

  it('rejects an absent SCD @InResponseTo, with inresponseto_missing', () => {
    expect(() => checkSubjectInResponseTo(withIrt([]), '_req-0001', ctx())).toThrow(
      UnauthorizedError
    );
    expect(rejectionReason()).toBe('inresponseto_missing');
  });

  it('requires EVERY value to match, not merely one of them', () => {
    expect(() =>
      checkSubjectInResponseTo(withIrt(['_req-0001', '_other-live']), '_req-0001', ctx())
    ).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('inresponseto_mismatch');
  });
});

// ============================================================================
// H-6 / M-5 — reject reasons that were DECLARED but never asserted
// ============================================================================

describe('H-6 declared reject reasons are exercised', () => {
  const ctx = (): SamlLogContext => ({
    ssoConfigId: SSO_CONFIG_ID,
    teamId: TEAM_ID,
    correlation: 'none',
  });

  it('session_not_consumed fires when the atomic consume matches zero rows', async () => {
    // This guard is the compensation for the TOCTOU that
    // `sso-session-cache.ts:11-16` documents in node-saml ("never inspects
    // removeAsync's return value"; "a reachable path where removeAsync is not
    // called at all"). Both tests named for the session gate asserted
    // `library_validation_failed` — i.e. node-saml rejecting first — so the
    // compensation itself had zero coverage.
    //
    // The zero-row consume is exactly what the LOSER of two concurrent POSTs
    // observes: the `WHERE status = 'pending'` predicate is re-evaluated under
    // READ COMMITTED and matches nothing. Reached on the library-ACCEPTED path
    // (an assertion whose SubjectConfirmationData carries no @InResponseTo never
    // causes node-saml to call removeAsync itself).
    consumeMatchesZeroRows = true;
    await expectRejection(post({ noScdInResponseTo: true }), 'session_not_consumed');
  });

  it('assertion_id_invalid fires for an over-length Assertion/@ID', async () => {
    // Executed against node-saml: a 701-character `Assertion/@ID` is ACCEPTED,
    // so this cap is the only bound before the value reaches the replay table.
    const longId = `_${'a'.repeat(700)}`;
    await expectRejection(
      toPostBody(signAssertion(buildResponse({ assertionId: longId }), longId)),
      'assertion_id_invalid'
    );
  });

  it('assertion_id_missing fires when the assertion carries no ID', () => {
    const profile = {
      getAssertion: () => ({
        Assertion: {
          Issuer: [{ _: IDP_ENTITY_ID }],
          Subject: [{ NameID: [{ _: DEFAULT_EMAIL }] }],
          Conditions: [{ $: { NotBefore: '2026-01-01T00:00:00Z', NotOnOrAfter: '2030-01-01T00:00:00Z' } }],
        },
      }),
    } as unknown as Profile;
    expect(() => readVerifiedAssertion(profile, ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('assertion_id_missing');
  });

  it('assertion_unreadable fires when the profile yields no Assertion object', () => {
    expect(() =>
      readVerifiedAssertion({ getAssertion: () => ({}) } as unknown as Profile, ctx())
    ).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('assertion_unreadable');

    // The other shape: no `getAssertion` at all, which is what a future library
    // version dropping the method would produce.
    expect(() => readVerifiedAssertion({} as unknown as Profile, ctx())).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('assertion_unreadable');
  });

  it('user_provisioning_failed keeps a raw pg error out of the response (NEW-3)', async () => {
    // `INSERT INTO users` sat outside every try/catch. A unique violation on
    // `users.email` — two concurrent first-time SSO logins for one address, or a
    // race against self-registration — threw a raw `pg` error out of
    // `processSAMLResponse`; not an AppError, so `errorHandler.ts:84` echoes
    // `err.message` to the client in dev.
    userInsertThrows = true;
    await expect(
      processSAMLResponse(post({ email: 'bob@example.test', nameId: 'bob@example.test' }), SSO_CONFIG_ID)
    ).rejects.toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('user_provisioning_failed');
    expect(generateTokens).not.toHaveBeenCalled();
    // And the client message stays the constant — no schema detail leaks.
    await expect(
      processSAMLResponse(post({ email: 'bob@example.test', nameId: 'bob@example.test' }), SSO_CONFIG_ID)
    ).rejects.toThrow(SAML_GENERIC_FAILURE);
  });

  it('a promotion that matches zero rows still authenticates, but is RECORDED (NEW-3 / L-1)', async () => {
    // `promoteSessionToCompleted` discarded its result, so a lost promotion
    // silently under-counted successful logins in the table that IS the SSO
    // evidence source. It must not fail the login — every gate has passed — but
    // it must not be silent either.
    promotionMatchesZeroRows = true;
    const result = await processSAMLResponse(post(), SSO_CONFIG_ID);
    expect(result.user.email).toBe(DEFAULT_EMAIL);
    expect(loggerCalls.some((c) => rejectionReasonOf(c) === 'session_promotion_missed')).toBe(true);
  });

  it('email_missing: the invariant it depends on is pinned', async () => {
    // `email_missing` is a defence-in-depth backstop in `resolveSSOUser` and is
    // UNREACHABLE by construction, proved by execution rather than asserted:
    // xml2js maps empty and whitespace-only element content to the plain string
    // '' (not `{ _: '' }`), `textOf` drops anything that is not a record, and
    // `readAttributes` skips an attribute once every value has been dropped. So
    // the mapped email attribute can never hold an empty value to override the
    // already-non-empty <NameID> with.
    //
    // Deleting the guard would be the wrong trade — it is the thing that fails
    // closed the day that parse behaviour changes — so the INVARIANT is pinned
    // here instead. If xml2js ever starts surfacing empty values, this goes red
    // and the guard becomes reachable.
    const result = await processSAMLResponse(
      post({
        extraAttributes:
          '<saml:Attribute Name="blank"><saml:AttributeValue></saml:AttributeValue>' +
          '<saml:AttributeValue> </saml:AttributeValue></saml:Attribute>',
      }),
      SSO_CONFIG_ID
    );
    expect(result.user.email).toBe(DEFAULT_EMAIL);

    const store = new Map<string, string>([[DEFAULT_REQUEST_ID, new Date().toISOString()]]);
    const saml = new SAML({
      callbackUrl: SP_ACS_URL,
      issuer: SP_ENTITY_ID,
      idpCert: IDP_PUBLIC_KEY_PEM,
      audience: SP_ENTITY_ID,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: 600_000,
      acceptedClockSkewMs: 60_000,
      cacheProvider: {
        saveAsync: async (k: string, val: string) => {
          store.set(k, val);
          return { value: val, createdAt: Date.now() };
        },
        getAsync: async (k: string) => store.get(k) ?? null,
        removeAsync: async (k: string | null) => (k !== null && store.delete(k) ? k : null),
      } as never,
    });
    const xml = signAssertion(
      buildResponse({
        extraAttributes:
          '<saml:Attribute Name="blank"><saml:AttributeValue></saml:AttributeValue></saml:Attribute>',
      }),
      DEFAULT_ASSERTION_ID
    );
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: toPostBody(xml) });
    const read = readVerifiedAssertion(profile as Profile, ctx());
    // The empty attribute is DROPPED, not stored as ''.
    expect(read.attributes.has('blank')).toBe(false);
    // And the value the guard defends is already required non-empty.
    expect(read.nameId.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// H-5 — single-use is an OUTCOME, not a matched SQL substring
// ============================================================================

describe('H-5 the atomic consume is single-use', () => {
  it('a second consume of the same request id yields nothing', async () => {
    // The only atomicity test asserted on the SOURCE TEXT of the emitted
    // template (`s.includes("SET status = 'failed'")`, `toContain('RETURNING
    // id')`), which holds for an implementation whose `WHERE status = 'pending'`
    // predicate has been deleted. This asserts the OUTCOME instead.
    //
    // Scope, stated plainly: this is the mock's model of the predicate, not a
    // concurrency proof. The concurrency claim itself
    // (`sso-session-cache.ts:118-121`, READ COMMITTED EvalPlanQual) was verified
    // by CISO against a real PostgreSQL at 25 rounds x 20-way concurrency —
    // 25 winners for 25 rounds on both the consume and the assertion-ID claim.
    // That, not this test, is the evidence for atomicity under contention.
    const provider = new SsoSessionCacheProvider(SSO_CONFIG_ID);

    expect(await provider.removeAsync(DEFAULT_REQUEST_ID)).toBe(DEFAULT_REQUEST_ID);
    expect(provider.consumedSessionId).not.toBeNull();

    const second = new SsoSessionCacheProvider(SSO_CONFIG_ID);
    expect(await second.removeAsync(DEFAULT_REQUEST_ID)).toBeNull();
    expect(second.consumedSessionId).toBeNull();
    expect(second.consumedRequestId).toBeNull();
  });

  it('a consumed row cannot be re-consumed by replaying the whole POST', async () => {
    const body = post();
    await processSAMLResponse(body, SSO_CONFIG_ID);
    expect(sessions.find((s) => s.request_id === DEFAULT_REQUEST_ID)?.status).toBe('completed');

    await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
    expect(generateTokens).toHaveBeenCalledTimes(1);
  });
});

// ============================================================================
// LOG-001 supplement — the silencing errorHandler must be load-bearing
// ============================================================================

describe('LOG-001 the DOMParser errorHandler is what suppresses xmldom', () => {
  it('a default parser writes attacker text to console.error; parseResponseDom writes none', () => {
    // Without this comparison the "zero console output" assertion elsewhere could
    // pass simply because the parser was never reached, rather than because it
    // was silenced — a false assurance, which is worse than no test.
    const bad = malformedEntityBody(30);

    // @xmldom/xmldom does NOT throw on this: it returns a partial document and
    // writes one console.error line per bad reference. try/catch cannot
    // intercept any of it, and the call count is attacker-controlled, which
    // makes it a log-volume amplifier on an unauthenticated endpoint.
    new DOMParser().parseFromString(bad, 'text/xml');
    const defaultCalls = consoleErrorSpy.mock.calls.length;
    consoleErrorSpy.mockClear();

    // The same body through our parser. It writes NOTHING, and it now also
    // REJECTS: the root element really is <samlp:Response> and only its content
    // is malformed, so before NEW-1 this returned a partial document and the
    // request continued into node-saml and then into xml-crypto. Silencing our
    // own channel was never enough — the parser we do not own has its own.
    expect(() =>
      parseResponseDom(bad, { ssoConfigId: SSO_CONFIG_ID, teamId: TEAM_ID, correlation: 'none' })
    ).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('response_not_wellformed');
    const silencedCalls = consoleErrorSpy.mock.calls.length;

    expect(defaultCalls).toBeGreaterThanOrEqual(30);
    expect(silencedCalls).toBe(0);
  });

  it('NEW-1 a WARNING-class document is rejected before node-saml, so xml-crypto never parses it', async () => {
    // The screen has to fire on warnings, not only on errors. Parity was
    // measured, not assumed: for each of these bodies the count our
    // record-and-reject handler observes equals the number of console writes
    // xmldom's DEFAULT handler produces — 1/1, 3/3, 2/2 — which is what makes
    // "our parser saw it" equivalent to "xml-crypto would have printed it".
    const signed = signAssertion(buildResponse(), DEFAULT_ASSERTION_ID);

    for (const count of [1, 50]) {
      sessions = [];
      addPendingSession();
      const body = toPostBody(withUnquotedAttributes(signed, count));
      await expect(processSAMLResponse(body, SSO_CONFIG_ID)).rejects.toThrow(UnauthorizedError);
      // Rejected by OUR screen — not by node-saml, which accepts this document,
      // and not by any later gate.
      expect(rejectionReason()).toBe('response_not_wellformed');
      expect(generateTokens).not.toHaveBeenCalled();
    }

    // Zero writes on every console channel, for the payload that used to produce
    // exactly `count` of them.
    expect(consoleWarnSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
    expect(consoleLogSpy).not.toHaveBeenCalled();
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it('NEW-1 the unmodified document still authenticates, so the screen is not rejecting everything', async () => {
    const result = await processSAMLResponse(
      toPostBody(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID)),
      SSO_CONFIG_ID
    );
    expect(result.user.email).toBe(DEFAULT_EMAIL);
  });

  it('NEW-1 the screen records WARNING-class input, which the old no-op handler could not', () => {
    // The previous handler was `() => {}`: it silenced OUR parser and returned a
    // partial document, so a warning-class body sailed on to node-saml and then
    // to xml-crypto. Silencing is not screening.
    const warningClass = '<samlp:Response xmlns:samlp="urn:x"><junk ATTACKERMARKER0=UNQUOTED/></samlp:Response>';
    expect(() =>
      parseResponseDom(warningClass, {
        ssoConfigId: SSO_CONFIG_ID,
        teamId: TEAM_ID,
        correlation: 'none',
      })
    ).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('response_not_wellformed');
    // And nothing about the attacker's marker reached any channel on the way.
    expect(consoleWarnSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('rejects a parsed document whose root element is not <Response>', () => {
    const ctx: SamlLogContext = {
      ssoConfigId: SSO_CONFIG_ID,
      teamId: TEAM_ID,
      correlation: 'none',
    };
    expect(() => parseResponseDom('<notaresponse/>', ctx)).toThrow(UnauthorizedError);
    expect(rejectionReason()).toBe('response_root_invalid');
  });

  it('the DTD filter the spec mandates catches what the old one evaded', () => {
    const evaded = withDoctype(signAssertion(buildResponse(), DEFAULT_ASSERTION_ID), DOCTYPE_CASINGS[1]);
    // The issue-2 filter, retracted:
    expect(evaded.includes('<!DOCTYPE')).toBe(false);
    // The required one:
    expect(/<!\s*doctype/i.test(evaded)).toBe(true);
  });
});

// ============================================================================
// TEST-014 supplement — the spoofing payload must really reach profile.issuer
// ============================================================================

describe('TEST-014 the profile write-through is real', () => {
  it('node-saml populates profile.issuer from <Attribute Name="issuer"> while the structural read stays empty', async () => {
    // Without this, TEST-014 could pass for the wrong reason — e.g. because the
    // attribute never reached the profile at all — and would stop proving that
    // reading `profile.issuer` is a bypass.
    const store = new Map<string, string>([[DEFAULT_REQUEST_ID, new Date().toISOString()]]);
    const saml = new SAML({
      callbackUrl: SP_ACS_URL,
      issuer: SP_ENTITY_ID,
      idpCert: IDP_PUBLIC_KEY_PEM,
      audience: SP_ENTITY_ID,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: 600_000,
      acceptedClockSkewMs: 60_000,
      cacheProvider: {
        saveAsync: async (k: string, val: string) => {
          store.set(k, val);
          return { value: val, createdAt: Date.now() };
        },
        getAsync: async (k: string) => store.get(k) ?? null,
        removeAsync: async (k: string | null) => (k !== null && store.delete(k) ? k : null),
      } as never,
    });

    const xml = signAssertion(
      buildResponse({
        issuer: null,
        extraAttributes:
          `<saml:Attribute Name="issuer"><saml:AttributeValue>${IDP_ENTITY_ID}` +
          `</saml:AttributeValue></saml:Attribute>`,
      }),
      DEFAULT_ASSERTION_ID
    );

    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: toPostBody(xml) });
    // Spoofed: an issuer check written against `profile` would read this and pass.
    expect((profile as unknown as Record<string, unknown>).issuer).toBe(IDP_ENTITY_ID);
    // Structural: the <Issuer> ELEMENT is genuinely absent, which is what
    // readVerifiedAssertion sees and rejects on.
    const parsed = (
      profile as unknown as { getAssertion: () => { Assertion: { Issuer?: unknown } } }
    ).getAssertion().Assertion;
    expect(parsed.Issuer).toBeUndefined();
  });
});

// ============================================================================
// REQ-011 — the SP-initiated flow and its three audit columns survive
// ============================================================================

describe('REQ-011 initiateSAMLLogin', () => {
  const config = (): SSOConfig => ({
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
  });

  it('creates the pending row through the cache provider, preserving relay state, IP and user agent', async () => {
    // node-saml's saveAsync(key, value) has no room for these three, so they
    // travel on the provider's constructor. If that wiring were dropped, three
    // columns of SSO audit data would vanish silently — this is the assertion
    // that notices.
    const { redirectUrl, requestId } = await initiateSAMLLogin(
      config(),
      'relay-abc',
      '203.0.113.9',
      'test-agent'
    );

    expect(requestId).toMatch(/^_[0-9a-f-]{36}$/);
    expect(redirectUrl).toContain('https://idp.example.test/sso?SAMLRequest=');
    expect(redirectUrl).toContain('RelayState=relay-abc');

    const row = sessions.find((s) => s.request_id === requestId);
    expect(row?.status).toBe('pending');
    expect(row?.relay_state).toBe('relay-abc');
    expect(row?.ip_address).toBe('203.0.113.9');
    expect(row?.user_agent).toBe('test-agent');
    expect(executed.filter((s) => s.includes('INSERT INTO sso_sessions'))).toHaveLength(1);
  });

  it('omits RelayState from the redirect when none was supplied', async () => {
    const { redirectUrl } = await initiateSAMLLogin(config());
    expect(redirectUrl).not.toContain('RelayState=');
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
