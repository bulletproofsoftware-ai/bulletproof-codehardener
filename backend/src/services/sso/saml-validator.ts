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
  | 'response_not_wellformed'
  | 'doctype_forbidden'
  | 'library_validation_failed'
  | 'idp_cert_unusable'
  | 'assertion_unreadable'
  | 'assertion_malformed'
  | 'issuer_missing'
  | 'issuer_mismatch'
  | 'conditions_missing'
  | 'conditions_incomplete'
  | 'conditions_expired'
  | 'conditions_not_yet_valid'
  | 'recipient_missing'
  | 'recipient_mismatch'
  | 'destination_mismatch'
  | 'inresponseto_missing'
  | 'inresponseto_mismatch'
  | 'weak_signature_algorithm'
  | 'signature_algorithm_divergence'
  | 'assertion_id_missing'
  | 'assertion_id_invalid'
  | 'assertion_replayed'
  | 'session_not_consumed'
  | 'user_not_in_team'
  | 'user_not_sso_linked'
  /**
   * Defence-in-depth backstop in `resolveSSOUser`. Executed probing shows it is
   * currently UNREACHABLE by construction: `readVerifiedAssertion` already
   * requires a non-empty `<NameID>`, and xml2js maps empty or whitespace-only
   * element content to the plain string `''` (not `{ _: '' }`), which `textOf`
   * drops — so `readAttributes` can never store an empty attribute value for the
   * mapped email attribute to override it with. The invariant that guard depends
   * on is pinned by a test; the guard stays because losing it silently the day
   * that parse behaviour changes would be an authentication defect.
   */
  | 'email_missing'
  | 'user_provisioning_failed'
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
 * `@node-saml/node-saml` normalises line endings before handing the document to
 * `xml-crypto` (`xml.js` `normalizeNewlines`). The well-formedness screen below
 * must see the SAME octets `xml-crypto` will parse, or a diagnostic that only
 * appears after normalisation would slip past it.
 */
function normalizeNewlines(xml: string): string {
  return xml.replace(/\r\n?/g, '\n');
}

/**
 * Parse the raw response, and REJECT any document that is not strictly
 * well-formed.
 *
 * Two jobs, in this order:
 *
 * 1. WELL-FORMEDNESS SCREEN (§B.3.1 note). This is not a security read of
 *    unverified data — no value from this document reaches any decision here —
 *    so it does not violate the "verified bytes only" rule. It exists because
 *    THREE parsers see the attacker's body and only two of them are ours to
 *    configure: `xml-crypto` calls `new xmldom.DOMParser().parseFromString(xml)`
 *    with NO options (`signed-xml.js:179`, `:456`, `:645`), which gives it
 *    xmldom's default handler — `warning` writes to `console.warn`, `error` to
 *    `console.error`. An unquoted attribute value is a xmldom *warning*, which
 *    node-saml's strict parse does NOT reject, so such a document survives to
 *    signature verification and writes attacker-chosen text to stderr, 1:1 with
 *    the number of malformations (executed: 1/50 attrs -> 1/50 writes, on a
 *    response that authenticated successfully). Rejecting warning-class
 *    documents here — before node-saml, therefore before xml-crypto — is what
 *    makes REQ-009 / AC-10 true rather than merely asserted. It also collapses
 *    the three-parser behavioural divergence into one.
 *
 *    The handler RECORDS rather than no-ops: silencing alone left the channel
 *    open in the parser we do not own.
 *
 * 2. The two non-authoritative reads we are allowed to make from the raw
 *    response: the advisory `Destination` check and the algorithm pin. Both run
 *    only after `validateSignedResponse` has succeeded.
 *
 * `@xmldom/xmldom` 0.8.x does NOT throw on malformed input — it returns a
 * partial document — so `try`/`catch` cannot substitute for this handler.
 */
export function parseResponseDom(responseXml: string, ctx: SamlLogContext): Document {
  let diagnostics = 0;
  const record = (): void => {
    diagnostics += 1;
  };
  const doc = new DOMParser({
    locator: {},
    // Never `(msg) => ...`: the message embeds attacker-chosen text, and this
    // module's whole logging discipline is that no attacker value is ever
    // carried anywhere. The COUNT is all we keep, and even that is not logged.
    errorHandler: { warning: record, error: record, fatalError: record },
  }).parseFromString(normalizeNewlines(responseXml), 'text/xml');

  if (diagnostics > 0) {
    rejectSaml('response_not_wellformed', ctx);
  }

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

/**
 * First element in DOCUMENT ORDER, strictly below `root`, whose `localName`
 * matches — in ANY namespace.
 *
 * This deliberately mirrors `xml-crypto`'s `xpath.select1(".//*[local-name(.)=
 * 'X']/@Algorithm", signatureNode)` (`signed-xml.js:462`, `:469`) exactly:
 * descendant-or-self of the signature EXCLUDING the signature element itself,
 * namespace-agnostic, first hit wins. It is not how WE would select a node — it
 * is how the library that performs the cryptography selects one, which is the
 * only selection whose result is load-bearing.
 */
function firstDescendantByLocalName(root: Element, localName: string): Element | null {
  const kids = root.childNodes;
  for (let i = 0; i < kids.length; i += 1) {
    const node = kids[i];
    if (node == null || node.nodeType !== 1) continue;
    const el = node as Element;
    if (el.localName === localName) return el;
    const nested = firstDescendantByLocalName(el, localName);
    if (nested !== null) return nested;
  }
  return null;
}

// ============================================================================
// §B.15 — signature / digest / canonicalization algorithm pinning
// ============================================================================

/** The four algorithm facts a signature commits to. */
interface SignatureAlgorithms {
  canonicalization: string;
  signature: string;
  digest: string;
  transforms: string[];
  referenceUri: string;
}

const NO_ALGORITHM = '';

function algorithmOf(element: Element | null): string {
  return element === null ? NO_ALGORITHM : element.getAttribute('Algorithm') ?? NO_ALGORITHM;
}

/**
 * OUR reading: namespace-qualified DIRECT children, the strict SAML-shaped
 * layout. Cardinality is asserted at every level, so this read is unambiguous
 * by construction.
 */
function structuralAlgorithms(signature: Element, ctx: SamlLogContext): SignatureAlgorithms {
  const signedInfos = elementChildren(signature, 'SignedInfo', DS_NS);
  if (signedInfos.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const signedInfo = signedInfos[0];

  const signatureMethods = elementChildren(signedInfo, 'SignatureMethod', DS_NS);
  if (signatureMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);

  const c14nMethods = elementChildren(signedInfo, 'CanonicalizationMethod', DS_NS);
  if (c14nMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);

  // xml.js:73-87 already requires exactly one Reference on anything it verifies.
  // Asserted again here so this control does not depend on that.
  const references = elementChildren(signedInfo, 'Reference', DS_NS);
  if (references.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const reference = references[0];

  const digestMethods = elementChildren(reference, 'DigestMethod', DS_NS);
  if (digestMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);

  // NEW-2: exactly one <Transforms>, never zero. The previous `for … of` over a
  // possibly-empty list meant "no <Transforms>" silently SKIPPED the allowlist —
  // the same "absence => pass" shape §B.4 exists to eliminate.
  const transformsNodes = elementChildren(reference, 'Transforms', DS_NS);
  if (transformsNodes.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const transformNodes = elementChildren(transformsNodes[0], 'Transform', DS_NS);
  if (transformNodes.length === 0) rejectSaml('weak_signature_algorithm', ctx);

  return {
    canonicalization: algorithmOf(c14nMethods[0]),
    signature: algorithmOf(signatureMethods[0]),
    digest: algorithmOf(digestMethods[0]),
    transforms: transformNodes.map(algorithmOf),
    referenceUri: reference.getAttribute('URI') ?? '',
  };
}

/**
 * XML-CRYPTO'S reading — the one that decides which cryptography actually runs.
 *
 * Reproduced from the installed `xml-crypto@6.1.2` build, not from its docs:
 *   - `signed-xml.js:462` c14n      = `.//*[local-name(.)='CanonicalizationMethod']/@Algorithm`
 *   - `signed-xml.js:469` signature = `.//*[local-name(.)='SignatureMethod']/@Algorithm`
 *   - `signed-xml.js:474` SignedInfo = `utils.findChildren(signatureNode, 'SignedInfo')`
 *   - `signed-xml.js:497` Reference  = `utils.findChildren(signedInfo, 'Reference')`
 *   - `signed-xml.js:517` digest     = `utils.findChildren(refNode, 'DigestMethod')[0]`
 *   - `signed-xml.js:540` transforms = `findChildren(refNode,'Transforms')[0]` -> `Transform` children
 * `utils.findChildren` (`utils.js:28-40`) treats a null namespace as "match any",
 * so every one of those is NAMESPACE-AGNOSTIC, and the first two are DESCENDANT
 * searches over the whole `<ds:Signature>` subtree in document order.
 *
 * A decoy `<x:SignatureMethod>` planted before `<ds:SignedInfo>` therefore
 * chooses the verification algorithm while sitting OUTSIDE the signed octets:
 * `SignatureValue` covers `canon(SignedInfo)` only, and the enveloped-signature
 * transform strips the whole `<ds:Signature>` subtree from the assertion digest.
 * Executed divergence proof and the SHA-1 chosen-prefix chain it re-enables:
 * `.conductor/reviews/ADVERSARIAL-review-saml.md` H-1.
 */
function effectiveAlgorithms(signature: Element, ctx: SamlLogContext): SignatureAlgorithms {
  const signedInfos = elementChildren(signature, 'SignedInfo', null);
  if (signedInfos.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const signedInfo = signedInfos[0];

  const references = elementChildren(signedInfo, 'Reference', null);
  if (references.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const reference = references[0];

  const digestMethods = elementChildren(reference, 'DigestMethod', null);
  if (digestMethods.length !== 1) rejectSaml('weak_signature_algorithm', ctx);

  const transformsNodes = elementChildren(reference, 'Transforms', null);
  if (transformsNodes.length !== 1) rejectSaml('weak_signature_algorithm', ctx);
  const transformNodes = elementChildren(transformsNodes[0], 'Transform', null);
  if (transformNodes.length === 0) rejectSaml('weak_signature_algorithm', ctx);

  return {
    canonicalization: algorithmOf(firstDescendantByLocalName(signature, 'CanonicalizationMethod')),
    signature: algorithmOf(firstDescendantByLocalName(signature, 'SignatureMethod')),
    digest: algorithmOf(digestMethods[0]),
    transforms: transformNodes.map(algorithmOf),
    referenceUri: reference.getAttribute('URI') ?? '',
  };
}

function sameAlgorithms(a: SignatureAlgorithms, b: SignatureAlgorithms): boolean {
  return (
    a.canonicalization === b.canonicalization &&
    a.signature === b.signature &&
    a.digest === b.digest &&
    a.referenceUri === b.referenceUri &&
    a.transforms.length === b.transforms.length &&
    a.transforms.every((value, index) => value === b.transforms[index])
  );
}

/**
 * Reading algorithms back from the raw DOM is the ONE legitimate exception to
 * "never trust the raw response", and it is sound for a specific reason:
 * `<SignedInfo>` IS precisely the octet stream that `<SignatureValue>` covers.
 * Tampering with any attribute inside it invalidates the signature, which
 * node-saml has already verified by the time this runs.
 *
 * That reasoning holds only for the RIGHT `<Signature>` element AND for the
 * right node WITHIN it. Selection of the element is structural (position in the
 * tree). Selection within it is done TWICE — once the way this module reads a
 * SAML signature, once the way `xml-crypto` actually resolved it — and the two
 * must agree. §0.3 forbids letting attacker-supplied data choose which object
 * you validate; H-1 showed that rule has to hold at the library boundary too,
 * not only at the document level.
 *
 * The allowlists are applied to the EFFECTIVE values — what ran — never to the
 * structural ones alone. Must run AFTER validation, never before.
 */
function pinSignatureElement(signature: Element, ownerId: string | null, ctx: SamlLogContext): void {
  const structural = structuralAlgorithms(signature, ctx);
  const effective = effectiveAlgorithms(signature, ctx);

  // Any disagreement means there is more than one candidate node and the
  // library picked one we did not inspect. There is no safe way to continue:
  // the value we would pin is not the value that ran.
  if (!sameAlgorithms(structural, effective)) {
    rejectSaml('signature_algorithm_divergence', ctx);
  }

  if (!ALLOWED_SIGNATURE_ALGORITHMS.has(effective.signature)) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  if (effective.canonicalization !== EXCLUSIVE_C14N) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  // The digest is what a chosen-prefix collision attack targets, and
  // chosen-prefix SHA-1 collisions have been practical at commodity cost since
  // 2020. A strong signature over a SHA-1 digest is the dangerous shape.
  if (!ALLOWED_DIGEST_ALGORITHMS.has(effective.digest)) {
    rejectSaml('weak_signature_algorithm', ctx);
  }

  for (const transform of effective.transforms) {
    if (!ALLOWED_TRANSFORMS.has(transform)) {
      rejectSaml('weak_signature_algorithm', ctx);
    }
  }

  // POST-SELECTION consistency assertion — never the selector. `Reference/@URI`
  // is the one field an attacker sets freely, so it may confirm a structural
  // choice but must never make one.
  if (ownerId === null || effective.referenceUri !== `#${ownerId}`) {
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
  /** Always present: `readVerifiedAssertion` rejects an assertion without it. */
  conditionsNotBefore: string;
  /** Always present: `readVerifiedAssertion` rejects an assertion without it. */
  conditionsNotOnOrAfter: string;
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

  // H-2 — the element being PRESENT is not enough.
  //
  // `saml.js:842` is `if (conditions && conditions.$)`. xml2js only emits the
  // `$` key when an element carries at least one attribute, so a `<Conditions>`
  // with ZERO attributes has no `$` and node-saml skips its ENTIRE timestamp
  // block — NotBefore and NotOnOrAfter are never enforced. The audience check
  // sits outside that guard, so the assertion is accepted rather than erroring.
  // Executed: an assertion with `IssueInstant` backdated one year and
  // `<Conditions/>` bare AUTHENTICATES. `NotOnOrAfter`-only is likewise accepted
  // with no lower bound. That defeats REQ-004 outright for anyone holding a
  // valid signature, so both attributes are required HERE and the window is
  // enforced by `checkConditionsWindow` below rather than delegated.
  const notBefore = attrOf(conditions, 'NotBefore');
  const notOnOrAfter = attrOf(conditions, 'NotOnOrAfter');
  if (notBefore === null || notBefore.length === 0) rejectSaml('conditions_incomplete', ctx);
  if (notOnOrAfter === null || notOnOrAfter.length === 0) rejectSaml('conditions_incomplete', ctx);

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
    conditionsNotBefore: notBefore,
    conditionsNotOnOrAfter: notOnOrAfter,
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
 * §B.? / REQ-004 — enforce the assertion lifetime OURSELVES.
 *
 * node-saml does enforce this window, but only for assertions whose
 * `<Conditions>` element carries at least one attribute (`saml.js:842`,
 * `if (conditions && conditions.$)`). `readVerifiedAssertion` now makes both
 * attributes mandatory, which closes that gap at the input; this function is
 * what makes the enforcement OURS rather than a property of a third-party
 * `if`. Same clock, same `SAML_CLOCK_SKEW_MS` the library is configured with, so
 * the accepted window is identical and an in-skew assertion still authenticates.
 *
 * Unparseable timestamps are `conditions_incomplete`, not a silent pass: this is
 * the exact place where `Number.isNaN(...) ? accept : compare` would reopen H-2.
 */
export function checkConditionsWindow(assertion: VerifiedAssertion, ctx: SamlLogContext): void {
  const notBefore = Date.parse(assertion.conditionsNotBefore);
  const notOnOrAfter = Date.parse(assertion.conditionsNotOnOrAfter);
  if (Number.isNaN(notBefore) || Number.isNaN(notOnOrAfter)) {
    rejectSaml('conditions_incomplete', ctx);
  }

  const now = Date.now();
  if (now < notBefore - samlClockSkewMs) rejectSaml('conditions_not_yet_valid', ctx);
  if (now >= notOnOrAfter + samlClockSkewMs) rejectSaml('conditions_expired', ctx);
}

/**
 * How long a consumed assertion ID must be remembered: exactly as long as the
 * assertion could still be replayed successfully, i.e. its own `NotOnOrAfter`
 * plus the accepted clock skew, floored so a pathologically short window still
 * leaves a usable record. Beyond that the row carries no security value.
 */
export function assertionReplayExpiry(assertion: VerifiedAssertion): Date {
  const floor = Date.now() + ASSERTION_REPLAY_MIN_RETENTION_MS;
  const notOnOrAfter = Date.parse(assertion.conditionsNotOnOrAfter);
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
