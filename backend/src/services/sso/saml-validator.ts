/**
 * SAML validation primitives — signature verification, algorithm pinning,
 * structural assertion reads, and the single sanitized rejection path.
 *
 * Library: `@node-saml/node-saml`, floor `^5.1.0`. That floor is load-bearing,
 * not cosmetic: 5.1.0 is the remediation release for CVE-2025-54419 and
 * CVE-2025-54369, and it is the release that stopped trusting DOM nodes and
 * started consuming only the byte range a signature actually covers
 * (`sig.getSignedReferences()[0]`). Anything <= 5.0.1 is unusable here.
 * Library evaluation, CVE history and executed evidence:
 * `.conductor/TODO/SPEC-saml-signature-verification.md` §A.
 *
 * Three controls in this file have NO library support and are entirely our code:
 *   - mandatory `<Issuer>`      (§B.4)  — node-saml only checks it on logout paths
 *   - `Recipient` / `Destination` (§B.7)  — the string "Recipient" appears nowhere in the package
 *   - algorithm pinning         (§B.15) — xml-crypto's permissive defaults accept SHA-1
 *
 * THE governing design principle, which this codebase got wrong twice during
 * review: never let attacker-supplied data choose WHICH object you validate.
 * Selection must be structural — position in the document tree. Attacker-
 * controlled identifiers may be used only as a post-selection assertion.
 */

import crypto from 'crypto';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import type { Profile } from '@node-saml/node-saml';
import { DOMParser } from '@xmldom/xmldom';
import { createLogger } from '../../utils/logger.js';
import { UnauthorizedError } from '../../middleware/errorHandler.js';
import { samlClockSkewMs } from '../../config/env.js';
import { SsoSessionCacheProvider } from './sso-session-cache.js';
import type { SSOConfig } from './saml.service.js';

const logger = createLogger('saml-validator');

/**
 * Every client-visible SAML failure is this exact string. `errorHandler` sends
 * `err.message` verbatim to the client for any `AppError`
 * (`errorHandler.ts:79`), so a variable message is a variable disclosure
 * channel — and an oracle an attacker can use to tune payloads.
 */
export const SAML_GENERIC_FAILURE = 'SAML authentication failed';

/** Max length of the base64 POST body, checked BEFORE any decode or parse. */
export const SAML_MAX_RESPONSE_BYTES = 1_048_576;

/** Max accepted length of `Assertion/@ID` before it reaches the replay store. */
const MAX_ASSERTION_ID_LENGTH = 512;

/** Floor for how long a consumed assertion ID is remembered. */
const ASSERTION_REPLAY_MIN_RETENTION_MS = 10 * 60 * 1000;

/** Matches the pre-existing 10-minute pending-session window. */
const REQUEST_ID_EXPIRATION_MS = 10 * 60 * 1000;

const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

const ALLOWED_SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set([
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
]);

const ALLOWED_DIGEST_ALGORITHMS: ReadonlySet<string> = new Set([
  'http://www.w3.org/2001/04/xmlenc#sha256',
  'http://www.w3.org/2001/04/xmlenc#sha512',
]);

const EXCLUSIVE_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED_SIGNATURE_TRANSFORM = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

const ALLOWED_TRANSFORMS: ReadonlySet<string> = new Set([
  ENVELOPED_SIGNATURE_TRANSFORM,
  EXCLUSIVE_C14N,
]);

/**
 * Closed union of our own literals. No attacker-derived value is ever
 * interpolated into a reason, which kills log injection structurally rather
 * than by escaping.
 */
export type SamlRejectReason =
  | 'sso_disabled'
  | 'config_missing'
  | 'config_disabled'
  | 'response_missing'
  | 'response_too_large'
  | 'response_root_invalid'
  | 'doctype_forbidden'
  | 'library_validation_failed'
  | 'idp_cert_unusable'
  | 'assertion_unreadable'
  | 'assertion_malformed'
  | 'issuer_missing'
  | 'issuer_mismatch'
  | 'conditions_missing'
  | 'recipient_missing'
  | 'recipient_mismatch'
  | 'destination_mismatch'
  | 'inresponseto_missing'
  | 'inresponseto_mismatch'
  | 'weak_signature_algorithm'
  | 'assertion_id_missing'
  | 'assertion_id_invalid'
  | 'assertion_replayed'
  | 'session_not_consumed'
  | 'user_not_in_team'
  | 'user_not_sso_linked'
  | 'email_missing'
  | 'user_not_provisionable';

/** Only values we own may appear here. Nothing attacker-derived. */
export interface SamlLogContext {
  /** Our UUID. */
  ssoConfigId: string;
  /** Our UUID, or null before the config has been loaded. */
  teamId: string | null;
  /** sha256(inResponseTo).slice(0, 12), or 'none'. Never the raw value. */
  correlation: string;
}

/**
 * The single rejection path. Always throws; never returns.
 *
 * The client gets a constant message so no check-identity leaks; the operator
 * gets the structured `reason` in the log. The library's own error text is
 * deliberately given up — node-saml embeds attacker values in its messages
 * (e.g. "audience mismatch ... Received: https://evil.test/").
 */
export function rejectSaml(reason: SamlRejectReason, ctx: SamlLogContext): never {
  logger.warn(
    {
      ssoConfigId: ctx.ssoConfigId,
      teamId: ctx.teamId,
      reason,
      correlation: ctx.correlation,
    },
    'SAML assertion rejected'
  );
  throw new UnauthorizedError(SAML_GENERIC_FAILURE);
}

/**
 * Correlation without disclosure. `inResponseTo` is attacker-supplied and must
 * never be logged raw.
 */
export function correlationOf(value: string | null | undefined): string {
  if (typeof value !== 'string' || value.length === 0) return 'none';
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

// ============================================================================
// Raw-body screening (§B.3.3, §B.7)
// ============================================================================

/**
 * Size-cap, decode, and reject any DTD — in that order, before node-saml or any
 * DOM parser sees the body.
 *
 * The DOCTYPE test is CASE-INSENSITIVE and whitespace-tolerant on purpose. XML
 * 1.0 requires the uppercase keyword, but `@xmldom/xmldom` 0.8.13 is more
 * lenient than the specification and happily parses `<!doctype` and
 * `<! DOCTYPE`. Executed: a validly signed response with a lowercase DTD
 * prepended evades `includes('<!DOCTYPE')` and is accepted end to end. Never
 * size a rejection filter to what the spec says a parser should accept.
 *
 * SAML 2.0 has no legitimate use for a DTD, so rejecting outright removes the
 * whole entity-declaration surface and the behavioural delta between
 * node-saml's parser and ours.
 */
export function decodeAndScreenResponse(samlResponse: unknown, ctx: SamlLogContext): string {
  if (typeof samlResponse !== 'string' || samlResponse.length === 0) {
    rejectSaml('response_missing', ctx);
  }
  if (samlResponse.length > SAML_MAX_RESPONSE_BYTES) {
    rejectSaml('response_too_large', ctx);
  }
  const decoded = Buffer.from(samlResponse, 'base64').toString('utf-8');
  if (/<!\s*doctype/i.test(decoded)) {
    rejectSaml('doctype_forbidden', ctx);
  }
  return decoded;
}

/**
 * Parse the raw response for the two non-authoritative reads we are allowed to
 * make from it: the advisory `Destination` check and the `SignedInfo` algorithm
 * read. Everything security-relevant otherwise comes from the verified bytes.
 *
 * The `errorHandler` is MANDATORY, not defensive style. `@xmldom/xmldom` 0.8.x
 * does NOT throw on malformed input: it writes attacker-controlled text to
 * `console.error` and returns a partial document, and `try`/`catch` cannot
 * intercept that. Executed: one crafted body with 30 bad entity references
 * produced 30 `console.error` calls with the default handler and 0 with this
 * one. Both the text and the call count are attacker-controlled.
 */
export function parseResponseDom(responseXml: string, ctx: SamlLogContext): Document {
  const doc = new DOMParser({ locator: {}, errorHandler: () => {} }).parseFromString(
    responseXml,
    'text/xml'
  );
  // localName !== 'Response' also covers null / partial-parse results.
  const root: Element | null = doc == null ? null : doc.documentElement;
  if (root === null || root.localName !== 'Response') {
    rejectSaml('response_root_invalid', ctx);
  }
  return doc;
}

/** The `<Response>` element. Callers have already been through parseResponseDom. */
function responseElement(doc: Document, ctx: SamlLogContext): Element {
  const root: Element | null = doc == null ? null : doc.documentElement;
  if (root === null || root.localName !== 'Response') {
    rejectSaml('response_root_invalid', ctx);
  }
  return root;
}

/** `Response/@InResponseTo` — on the UNSIGNED envelope, therefore untrusted. */
export function envelopeInResponseTo(doc: Document, ctx: SamlLogContext): string | null {
  return responseElement(doc, ctx).getAttribute('InResponseTo');
}

// ============================================================================
// DOM helpers — direct-child traversal only (§0.3)
// ============================================================================

/**
 * Direct element children matching `localName` (and `namespaceUri`, when given).
 *
 * Deliberately NOT `getElementsByTagName*`: that is a DESCENDANT search, and a
 * descendant search is exactly how a decoy `<Signature>` planted in
 * `<samlp:Extensions>` gets selected instead of the real one.
 */
function elementChildren(parent: Element, localName: string, namespaceUri: string | null): Element[] {
  const out: Element[] = [];
  const kids = parent.childNodes;
  for (let i = 0; i < kids.length; i += 1) {
    const node = kids[i];
    if (node == null || node.nodeType !== 1) continue;
    const el = node as Element;
    if (el.localName !== localName) continue;
    if (namespaceUri !== null && el.namespaceURI !== namespaceUri) continue;
    out.push(el);
  }
  return out;
}

// ============================================================================
// §B.15 — signature / digest / canonicalization algorithm pinning
// ============================================================================

/**
 * Reading algorithms back from the raw DOM is the ONE legitimate exception to
 * "never trust the raw response", and it is sound for a specific reason:
 * `<SignedInfo>` IS precisely the octet stream that `<SignatureValue>` covers.
 * Tampering with any of these attributes invalidates the signature, which
 * node-saml has already verified by the time this runs. So the values read back
 * are exactly the values that were used.
 *
 * That reasoning holds only for the RIGHT `<Signature>` element, which is why
 * selection below is structural. It must run AFTER validation, never before.
 */
function pinSignatureElement(signature: Element, ownerId: string | null, ctx: SamlLogContext): void {
  const signedInfos = elementChildren(signature, 'SignedInfo', DS_NS);
  if (signedInfos.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const signedInfo = signedInfos[0];

  const signatureMethods = elementChildren(signedInfo, 'SignatureMethod', DS_NS);
  if (signatureMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  if (!ALLOWED_SIGNATURE_ALGORITHMS.has(signatureMethods[0].getAttribute('Algorithm') ?? '')) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  const c14nMethods = elementChildren(signedInfo, 'CanonicalizationMethod', DS_NS);
  if (c14nMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  if ((c14nMethods[0].getAttribute('Algorithm') ?? '') !== EXCLUSIVE_C14N) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  // xml.js:73-87 already requires exactly one Reference on anything it verifies.
  // Asserted again here so this control does not depend on that.
  const references = elementChildren(signedInfo, 'Reference', DS_NS);
  if (references.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const reference = references[0];

  const digestMethods = elementChildren(reference, 'DigestMethod', DS_NS);
  if (digestMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  // The digest is what a chosen-prefix collision attack targets, and
  // chosen-prefix SHA-1 collisions have been practical at commodity cost since
  // 2020. A strong signature over a SHA-1 digest is the dangerous shape.
  if (!ALLOWED_DIGEST_ALGORITHMS.has(digestMethods[0].getAttribute('Algorithm') ?? '')) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  for (const transforms of elementChildren(reference, 'Transforms', DS_NS)) {
    for (const transform of elementChildren(transforms, 'Transform', DS_NS)) {
      if (!ALLOWED_TRANSFORMS.has(transform.getAttribute('Algorithm') ?? '')) {
        rejectSaml('weak_signature_algorithm', ctx);
      }
    }
  }

  // POST-SELECTION consistency assertion — never the selector. `Reference/@URI`
  // is the one field an attacker sets freely, so it may confirm a structural
  // choice but must never make one.
  if (ownerId === null || reference.getAttribute('URI') !== `#${ownerId}`) {
    rejectSaml('weak_signature_algorithm', ctx);
  }
}

/**
 * Pin the algorithms of every signature whose bytes could be consumed.
 *
 * Selection mirrors node-saml's own rule (`xml.js:52` searches only
 * `./*[local-name()='Signature']` on the node it is handed, and it is only ever
 * handed `<Response>` or `assertions[0]`). A `<ds:Signature>` planted inside
 * `<samlp:Extensions>` is a child of neither, so none of node-saml's seven
 * wrapping guards observe it — and `<samlp:Extensions>` precedes
 * `<saml:Assertion>` in SAML 2.0 schema order, so such a decoy wins document
 * order against any descendant search. Executed: with the decoy present, a
 * `Reference/@URI`-based selector reads the decoy's rsa-sha256 and passes
 * pinning while the real assertion is signed rsa-sha1.
 */
export function pinAlgorithms(doc: Document, ctx: SamlLogContext): void {
  const root = responseElement(doc, ctx);

  const assertions = elementChildren(root, 'Assertion', null);
  if (assertions.length !== 1) rejectSaml('assertion_malformed', ctx);
  const assertion = assertions[0];

  const assertionSignatures = elementChildren(assertion, 'Signature', DS_NS);
  if (assertionSignatures.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  pinSignatureElement(assertionSignatures[0], assertion.getAttribute('ID'), ctx);

  // §B.15.2 — `saml.js:562` sets `verifiedXml = responseVerifiedXml ||
  // assertionVerifiedXml`, so an envelope signature takes PRIORITY as the source
  // of the consumed bytes when present. Pinning only the assertion would leave
  // the consumed bytes verifiable under an unpinned algorithm. Zero is allowed
  // (the envelope signature is optional); more than one is a rejection.
  const responseSignatures = elementChildren(root, 'Signature', DS_NS);
  if (responseSignatures.length > 1) rejectSaml('weak_signature_algorithm', ctx);
  if (responseSignatures.length === 1) {
    pinSignatureElement(responseSignatures[0], root.getAttribute('ID'), ctx);
  }
}

// ============================================================================
// §B.3.1 — structural reads from the VERIFIED assertion bytes
// ============================================================================

type XmlRecord = Record<string, unknown>;

function asRecord(value: unknown): XmlRecord | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as XmlRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** xml2js runs with `explicitCharkey: true`, so element text lives under `_`. */
function textOf(value: unknown): string | null {
  const record = asRecord(value);
  if (record === null) return null;
  const text = record._;
  return typeof text === 'string' ? text : null;
}

/** Attributes live under `$`. */
function attrOf(value: unknown, name: string): string | null {
  const record = asRecord(value);
  if (record === null) return null;
  const attrs = asRecord(record.$);
  if (attrs === null) return null;
  const attr = attrs[name];
  return typeof attr === 'string' ? attr : null;
}

/**
 * Everything a security decision is allowed to read, taken structurally from
 * `profile.getAssertion().Assertion` — the xml2js parse of the VERIFIED
 * assertion bytes.
 */
export interface VerifiedAssertion {
  id: string;
  issuer: string;
  nameId: string;
  nameIdFormat: string;
  sessionIndex: string;
  attributes: Map<string, string | string[]>;
  /** Every `SubjectConfirmationData/@Recipient` present. */
  recipients: string[];
  /** Every `SubjectConfirmationData/@InResponseTo` present. */
  subjectInResponseTo: string[];
  conditionsNotBefore: string | null;
  conditionsNotOnOrAfter: string | null;
}

/**
 * NO security decision may read any property of `profile`.
 *
 * `saml.js:866-885` copies every SAML `<Attribute>` onto the profile object
 * keyed by its IdP-CONTROLLED name, guarded only by `hasOwnProperty`. An
 * assertion that omits `<Issuer>` entirely and carries
 * `<Attribute Name="issuer">` therefore fills `profile.issuer` with the
 * attacker's chosen value — executed, and it means an issuer check written
 * against `profile.issuer` passes its own test while the control is bypassed.
 * `<Attribute Name="__proto__">` from the same write-through replaces the
 * profile's prototype.
 *
 * The xml2js object read here has the opposite behaviour, confirmed by
 * execution: `<__proto__>` is recorded as an ordinary OWN key and does not
 * write through, and a second `<Issuer>` nested in `<Advice>` does not shadow
 * the real one.
 */
export function readVerifiedAssertion(profile: Profile, ctx: SamlLogContext): VerifiedAssertion {
  const parsed = typeof profile.getAssertion === 'function' ? profile.getAssertion() : null;
  const assertion = asRecord(asRecord(parsed)?.Assertion);
  if (assertion === null) rejectSaml('assertion_unreadable', ctx);

  // Cardinality first. SAML 2.0 Core permits exactly one <Issuer>, <Subject>,
  // <Subject>/<NameID> and <Conditions> per <Assertion>. xml2js returns arrays,
  // and "take [0] of N" is the shape that produces parser-differential bugs the
  // moment any other consumer reads the last one.
  const issuers = asArray(assertion.Issuer);
  if (issuers.length === 0) rejectSaml('issuer_missing', ctx);
  if (issuers.length !== 1) rejectSaml('assertion_malformed', ctx);

  const subjects = asArray(assertion.Subject);
  if (subjects.length !== 1) rejectSaml('assertion_malformed', ctx);
  const subject = asRecord(subjects[0]);
  if (subject === null) rejectSaml('assertion_malformed', ctx);

  const nameIds = asArray(subject.NameID);
  if (nameIds.length !== 1) rejectSaml('assertion_malformed', ctx);

  // <Conditions> absence must be an explicit rejection, not a TypeError we
  // tolerate by luck. Today an assertion with no <Conditions> dies inside
  // node-saml at `saml.js:849`; that is fail-closed, but by accident, and the
  // guarantee has to survive a future library refactor.
  const conditionsList = asArray(assertion.Conditions);
  if (conditionsList.length === 0) rejectSaml('conditions_missing', ctx);
  if (conditionsList.length !== 1) rejectSaml('assertion_malformed', ctx);
  const conditions = conditionsList[0];

  const issuer = textOf(issuers[0]);
  if (typeof issuer !== 'string' || issuer.length === 0) rejectSaml('issuer_missing', ctx);

  const id = attrOf(assertion, 'ID');
  if (id === null || id.length === 0) rejectSaml('assertion_id_missing', ctx);
  if (id.length > MAX_ASSERTION_ID_LENGTH) rejectSaml('assertion_id_invalid', ctx);

  const nameId = textOf(nameIds[0]);
  if (nameId === null || nameId.length === 0) rejectSaml('assertion_malformed', ctx);

  // One traversal serves both the Recipient check (§B.7) and the request-binding
  // check (§B.8.5), so the two cannot drift apart.
  const subjectConfirmationData = asArray(subject.SubjectConfirmation).flatMap((sc) =>
    asArray(asRecord(sc)?.SubjectConfirmationData)
  );

  const recipients = subjectConfirmationData
    .map((scd) => attrOf(scd, 'Recipient'))
    .filter((value): value is string => typeof value === 'string');

  const subjectInResponseTo = subjectConfirmationData
    .map((scd) => attrOf(scd, 'InResponseTo'))
    .filter((value): value is string => typeof value === 'string');

  return {
    id,
    issuer,
    nameId,
    nameIdFormat: attrOf(nameIds[0], 'Format') ?? '',
    sessionIndex: attrOf(asArray(assertion.AuthnStatement)[0], 'SessionIndex') ?? '',
    attributes: readAttributes(assertion),
    recipients,
    subjectInResponseTo,
    conditionsNotBefore: attrOf(conditions, 'NotBefore'),
    conditionsNotOnOrAfter: attrOf(conditions, 'NotOnOrAfter'),
  };
}

/**
 * Attribute VALUES still come from the IdP and are still untrusted data — they
 * are read into a Map, never used as object keys. A Map has no prototype chain
 * to write through and no inherited keys to read back by accident.
 */
function readAttributes(assertion: XmlRecord): Map<string, string | string[]> {
  const attributes = new Map<string, string | string[]>();
  for (const statement of asArray(assertion.AttributeStatement)) {
    for (const attribute of asArray(asRecord(statement)?.Attribute)) {
      const name = attrOf(attribute, 'Name');
      if (name === null || name.length === 0) continue;
      const values = asArray(asRecord(attribute)?.AttributeValue)
        .map((value) => textOf(value))
        .filter((value): value is string => typeof value === 'string');
      if (values.length === 0) continue;
      attributes.set(name, values.length === 1 ? values[0] : values);
    }
  }
  return attributes;
}

// ============================================================================
// Config-dependent policy checks
// ============================================================================

/**
 * §B.4 — mandatory issuer. Replaces the `if (issuer && issuer !== ...)`
 * short-circuit whose `issuer &&` guard turned a missing `<Issuer>` into a skip.
 *
 * Missing and wrong are BOTH rejections and are reported as DISTINCT reasons so
 * they stay separable in the audit log. Exact string equality: no trimming, no
 * case folding, no URL normalisation — SAML entity IDs are opaque strings. The
 * rejected value is never interpolated into the message or the log line.
 */
export function checkIssuer(
  assertion: VerifiedAssertion,
  config: SSOConfig,
  ctx: SamlLogContext
): void {
  if (assertion.issuer !== config.idpEntityId) rejectSaml('issuer_mismatch', ctx);
}

/**
 * §B.7 — `Recipient` is the AUTHORITATIVE binding control, because it is inside
 * the signature. Fail closed on absence: `if (recipient && recipient !== ...)`
 * would be the identical bug to the old issuer check. EVERY `Recipient` present
 * must match, not merely one of them.
 */
export function checkRecipient(
  assertion: VerifiedAssertion,
  config: SSOConfig,
  ctx: SamlLogContext
): void {
  if (assertion.recipients.length === 0) rejectSaml('recipient_missing', ctx);
  if (assertion.recipients.some((recipient) => recipient !== config.spAcsUrl)) {
    rejectSaml('recipient_mismatch', ctx);
  }
}

/**
 * §B.7 — `Destination` is an ADVISORY sanity gate, not a security boundary: it
 * sits on the `<Response>` envelope, which is unsigned unless the IdP also signs
 * the envelope, so it is attacker-controlled in the general case.
 *
 * Absent is ALLOWED (SAML 2.0 Core makes it optional on an unsigned response);
 * present-and-wrong is rejected. That asymmetry looks like the fail-open bug
 * §B.4 forbids and is deliberately not one — the authoritative check is
 * `Recipient`, above, which is inside the signature and is mandatory.
 */
export function checkDestination(doc: Document, config: SSOConfig, ctx: SamlLogContext): void {
  const destination = responseElement(doc, ctx).getAttribute('Destination');
  if (destination !== null && destination !== '' && destination !== config.spAcsUrl) {
    rejectSaml('destination_mismatch', ctx);
  }
}

/**
 * §B.8.5 — bind the assertion to the SP-initiated request.
 *
 * node-saml's own `SubjectConfirmationData/@InResponseTo` cross-check
 * (`saml.js:802-805`) only fires when the attribute is PRESENT. When it is
 * absent there is no binding check at all, and executed proof shows such an
 * assertion is accepted with the pending session left untouched — so a signed
 * assertion carrying no SCD `@InResponseTo` could be paired with ANY live
 * request id for that config, bound only by `Response/@InResponseTo` on the
 * unsigned envelope.
 *
 * `consumedRequestId` is the request id this flow ACTUALLY consumed, never the
 * attacker-mutable envelope attribute.
 */
export function checkSubjectInResponseTo(
  assertion: VerifiedAssertion,
  consumedRequestId: string,
  ctx: SamlLogContext
): void {
  if (assertion.subjectInResponseTo.length === 0) rejectSaml('inresponseto_missing', ctx);
  if (assertion.subjectInResponseTo.some((value) => value !== consumedRequestId)) {
    rejectSaml('inresponseto_mismatch', ctx);
  }
}

/**
 * How long a consumed assertion ID must be remembered: exactly as long as the
 * assertion could still be replayed successfully, i.e. its own `NotOnOrAfter`
 * plus the accepted clock skew, floored so a pathologically short window still
 * leaves a usable record. Beyond that the row carries no security value.
 */
export function assertionReplayExpiry(assertion: VerifiedAssertion): Date {
  const floor = Date.now() + ASSERTION_REPLAY_MIN_RETENTION_MS;
  const notOnOrAfter =
    assertion.conditionsNotOnOrAfter === null
      ? Number.NaN
      : Date.parse(assertion.conditionsNotOnOrAfter);
  const bound = Number.isNaN(notOnOrAfter) ? floor : notOnOrAfter + samlClockSkewMs;
  return new Date(Math.max(floor, bound));
}

// ============================================================================
// Validator construction
// ============================================================================

/**
 * One `SAML` instance per ACS request, plus the named cache-provider handle the
 * caller needs for `consumedSessionId` / `consumedRequestId`.
 *
 * The constructor is INSIDE the sanitized rejection path: it validates
 * `idpCert`, `callbackUrl`, `issuer` and the enum options, and throws a
 * `TypeError` whose message can embed configuration values. In dev,
 * `errorHandler` echoes `err.message` for non-`AppError` throws
 * (`errorHandler.ts:84`), so that must not escape.
 *
 * Both `catch` blocks in this module are deliberately BARE — no binding — so
 * there is no error variable in scope that a later edit could log or rethrow.
 */
export function createSamlValidator(
  config: SSOConfig,
  ctx: SamlLogContext
): { saml: SAML; provider: SsoSessionCacheProvider } {
  const provider = new SsoSessionCacheProvider(config.id);
  let saml: SAML;
  try {
    saml = new SAML({
      callbackUrl: config.spAcsUrl,
      issuer: config.spEntityId,
      // The pinned trust anchor. Passed straight through: node-saml's
      // `normalizePemFile()` handles line-ending and 64-column normalisation
      // itself, and every production-realistic shape (full PEM cert, bare
      // base64 cert body with or without newlines) is accepted.
      idpCert: config.idpCertificate,
      // Set for correctness of intent. NOT relied upon: `verifyIssuer()` is
      // reachable only from the logout paths (`saml.js:705`, `:717`), so the
      // login-path issuer check is ours — see checkIssuer above.
      idpIssuer: config.idpEntityId,
      audience: config.spEntityId,
      // The assertion signature is ALWAYS required. There is no branch anywhere
      // in this module that asks whether a signature is present.
      wantAssertionsSigned: true,
      // node-saml defaults this to true (`saml.js:85`). Deliberately false: with
      // wantAssertionsSigned true, a response-level-only signature is still
      // rejected, so this opens no hole — it only avoids rejecting the majority
      // of real IdPs that sign the assertion and not the envelope. It matches
      // the SP metadata we already publish (WantAssertionsSigned="true", no
      // demand for a signed response). If an envelope signature IS present, its
      // algorithms are pinned too — see pinAlgorithms.
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs: REQUEST_ID_EXPIRATION_MS,
      acceptedClockSkewMs: samlClockSkewMs,
      cacheProvider: provider,
    });
  } catch {
    rejectSaml('idp_cert_unusable', ctx);
  }
  return { saml, provider };
}

/**
 * Run node-saml's validation inside the sanitized path.
 *
 * `validatePostResponseAsync` throws messages that embed attacker-controlled
 * values, so the bare `catch` is load-bearing. A null profile or a logout
 * response is a rejection, never a fall-through.
 */
export async function validateSignedResponse(
  saml: SAML,
  samlResponse: string,
  ctx: SamlLogContext
): Promise<Profile> {
  let result: { profile: Profile | null; loggedOut: boolean };
  try {
    result = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });
  } catch {
    rejectSaml('library_validation_failed', ctx);
  }
  if (result.profile == null || result.loggedOut === true) {
    rejectSaml('library_validation_failed', ctx);
  }
  return result.profile;
}
