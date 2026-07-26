/**
 * SAML test fixtures — throwaway key material and a real XML signer.
 *
 * NO certificate or private key is committed to this repository. Both keypairs
 * are generated in-process at module import and never touch disk.
 *
 * Signing uses `xml-crypto`'s `SignedXml` — the same engine node-saml verifies
 * with — so a passing test proves real interop rather than a self-consistent
 * mock.
 *
 * This module is excluded from the TypeScript build (`tsconfig.json`
 * "src/**\/__fixtures__/**") so RSA key generation and SAML-response forging
 * helpers cannot be emitted into dist/. It may be imported only by tests.
 *
 * TODO / known coverage gap: these fixtures use an SPKI PUBLIC KEY PEM as
 * `idpCert`, because no X.509 certificate may be committed. That means the
 * suite cannot exercise production certificate-format normalisation (full PEM
 * certificate, and bare-base64 certificate body with or without newlines, which
 * are the shapes operators actually paste). Those shapes were verified by
 * execution against a throwaway self-signed certificate generated outside the
 * repo — see .conductor/evidence/saml-poc-5-cert-formats.js and §A.7 of the
 * spec. Note a bare-base64 SPKI body is REJECTED by node-saml (keyInfoToPem
 * wraps unarmoured base64 with a CERTIFICATE label), so the full SPKI PEM below
 * is required here; the bare body must not be substituted.
 */

import crypto from 'crypto';
import { SignedXml } from 'xml-crypto';

const keyOptions = {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
} as const;

// Generated ONCE per module import, not per test: 2048 bits keeps generation
// inside the 10s testTimeout.
const idpKeys = crypto.generateKeyPairSync('rsa', keyOptions);
// A second, independent pair standing in for an attacker who signs their own
// assertion with a key the SP has not pinned.
const attackerKeys = crypto.generateKeyPairSync('rsa', keyOptions);

/** The value that would live in `sso_configurations.idp_certificate`. */
export const IDP_PUBLIC_KEY_PEM = idpKeys.publicKey;
export const IDP_PRIVATE_KEY_PEM = idpKeys.privateKey;
export const ATTACKER_PRIVATE_KEY_PEM = attackerKeys.privateKey;

export const IDP_ENTITY_ID = 'https://idp.example.test/entity';
export const SP_ENTITY_ID = 'https://sp.example.test/entity';
export const SP_ACS_URL = 'https://sp.example.test/api/v1/sso/saml/acs/cfg-1';
export const SSO_CONFIG_ID = '11111111-1111-4111-8111-111111111111';
export const TEAM_ID = '22222222-2222-4222-8222-222222222222';
export const DEFAULT_REQUEST_ID = '_req-0001';
export const DEFAULT_ASSERTION_ID = '_assert-0001';
export const DEFAULT_EMAIL = 'alice@example.test';

export const SIG_ALG = {
  rsaSha256: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  rsaSha512: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  rsaSha1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
} as const;

export const DIGEST_ALG = {
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha1: 'http://www.w3.org/2000/09/xmldsig#sha1',
} as const;

export const C14N = {
  exclusive: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  inclusive: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
} as const;

const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

const iso = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();

export interface ResponseOverrides {
  assertionId?: string;
  responseId?: string;
  /** `null` omits the <Issuer> element entirely. */
  issuer?: string | null;
  /** Emits a second top-level <Issuer> inside the assertion. */
  duplicateIssuer?: boolean;
  duplicateSubject?: boolean;
  duplicateNameId?: boolean;
  notBefore?: string;
  notOnOrAfter?: string;
  /** Keeps SubjectConfirmationData valid while Conditions expires. */
  scdNotOnOrAfter?: string;
  audience?: string;
  noAudienceRestriction?: boolean;
  noConditions?: boolean;
  /**
   * Emit `<saml:Conditions>` with NO attributes at all. node-saml gates its
   * whole timestamp block on `conditions.$` (`saml.js:842`), and xml2js only
   * emits `$` for an element that has attributes — so this shape disables
   * NotBefore/NotOnOrAfter enforcement entirely inside the library. Executed: a
   * one-year-old assertion in this shape AUTHENTICATES against node-saml alone.
   */
  noConditionsAttributes?: boolean;
  /** Emit `<saml:Conditions>` carrying only `NotBefore`. */
  noConditionsNotOnOrAfter?: boolean;
  /** Emit `<saml:Conditions>` carrying only `NotOnOrAfter` — no lower bound. */
  noConditionsNotBefore?: boolean;
  recipient?: string;
  noRecipient?: boolean;
  /**
   * Emit a SECOND `<saml:SubjectConfirmation>` whose `SubjectConfirmationData`
   * carries this `Recipient`, keeping the first one valid. §B.7 requires EVERY
   * Recipient to match, not merely one — the shape that tells `.some` apart
   * from `.every`.
   */
  secondRecipient?: string;
  destination?: string;
  /** `Response/@InResponseTo`. */
  inResponseTo?: string;
  /** SubjectConfirmationData/@InResponseTo, set independently. */
  scdInResponseTo?: string;
  noScdInResponseTo?: boolean;
  email?: string;
  nameId?: string;
  /** Raw XML appended inside <AttributeStatement>. */
  extraAttributes?: string;
  /** Raw XML inserted as <samlp:Extensions> content, before <Assertion>. */
  extensions?: string;
  /** Injected verbatim just before </samlp:Response>. */
  extraAfterAssertion?: string;
  /** Wraps the assertion's content in <saml:Advice>. */
  adviceWrapped?: boolean;
}

/**
 * Emits a complete, spec-shaped <samlp:Response>. Every knob a test in the
 * suite needs is above; the response is unsigned until passed through
 * `signAssertion`.
 */
export function buildResponse(o: ResponseOverrides = {}): string {
  const assertionId = o.assertionId ?? DEFAULT_ASSERTION_ID;
  const responseId = o.responseId ?? '_resp-0001';
  const notOnOrAfter = o.notOnOrAfter ?? iso(300_000);
  const notBefore = o.notBefore ?? iso(-60_000);
  const scdNotOnOrAfter = o.scdNotOnOrAfter ?? notOnOrAfter;
  const audience = o.audience ?? SP_ENTITY_ID;
  const recipient = o.recipient ?? SP_ACS_URL;
  const destination = o.destination ?? SP_ACS_URL;
  const inResponseTo = o.inResponseTo ?? DEFAULT_REQUEST_ID;
  const scdInResponseTo = o.scdInResponseTo ?? inResponseTo;
  const email = o.email ?? DEFAULT_EMAIL;
  const nameId = o.nameId ?? email;

  const issuerValue = o.issuer === undefined ? IDP_ENTITY_ID : o.issuer;
  const issuerEl = issuerValue === null ? '' : `<saml:Issuer>${issuerValue}</saml:Issuer>`;
  const duplicateIssuerEl = o.duplicateIssuer
    ? `<saml:Issuer>https://evil.test/idp</saml:Issuer>`
    : '';

  const scdAttrs = [
    `NotOnOrAfter="${scdNotOnOrAfter}"`,
    o.noRecipient ? '' : `Recipient="${recipient}"`,
    o.noScdInResponseTo ? '' : `InResponseTo="${scdInResponseTo}"`,
  ]
    .filter(Boolean)
    .join(' ');

  const nameIdEl =
    `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>`;

  const secondScdAttrs = [
    `NotOnOrAfter="${scdNotOnOrAfter}"`,
    `Recipient="${o.secondRecipient ?? ''}"`,
    o.noScdInResponseTo ? '' : `InResponseTo="${scdInResponseTo}"`,
  ]
    .filter(Boolean)
    .join(' ');

  const secondConfirmation =
    o.secondRecipient === undefined
      ? ''
      : `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
        `<saml:SubjectConfirmationData ${secondScdAttrs}/>` +
        `</saml:SubjectConfirmation>`;

  const subjectInner =
    `${nameIdEl}${o.duplicateNameId ? nameIdEl : ''}` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData ${scdAttrs}/>` +
    `</saml:SubjectConfirmation>` +
    secondConfirmation;

  const subjectEl = `<saml:Subject>${subjectInner}</saml:Subject>`;

  const audienceEl = o.noAudienceRestriction
    ? ''
    : `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>`;

  const conditionsAttrs = o.noConditionsAttributes
    ? ''
    : [
        o.noConditionsNotBefore ? '' : ` NotBefore="${notBefore}"`,
        o.noConditionsNotOnOrAfter ? '' : ` NotOnOrAfter="${notOnOrAfter}"`,
      ].join('');

  const conditionsEl = o.noConditions
    ? ''
    : `<saml:Conditions${conditionsAttrs}>${audienceEl}</saml:Conditions>`;

  const attributeStatement =
    `<saml:AttributeStatement>` +
    `<saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute>` +
    `<saml:Attribute Name="name"><saml:AttributeValue>Alice Example</saml:AttributeValue></saml:Attribute>` +
    `${o.extraAttributes ?? ''}` +
    `</saml:AttributeStatement>`;

  const assertionBody =
    `${issuerEl}${duplicateIssuerEl}${subjectEl}${o.duplicateSubject ? subjectEl : ''}${conditionsEl}` +
    `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_session-1">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>` +
    `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` +
    `</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    attributeStatement;

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" ` +
    `Version="2.0" IssueInstant="${iso(0)}">` +
    (o.adviceWrapped ? `<saml:Advice>${assertionBody}</saml:Advice>` : assertionBody) +
    `</saml:Assertion>`;

  const extensions = o.extensions ? `<samlp:Extensions>${o.extensions}</samlp:Extensions>` : '';

  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" ` +
    `IssueInstant="${iso(0)}" Destination="${destination}" InResponseTo="${inResponseTo}">` +
    `<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
    extensions +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion +
    `${o.extraAfterAssertion ?? ''}` +
    `</samlp:Response>`
  );
}

export interface SignOptions {
  privateKey?: string;
  sigAlg?: string;
  digAlg?: string;
  c14n?: string;
}

/**
 * Sign the element carrying `id`.
 *
 * `location.action: 'prepend'` inside the referenced element makes the
 * signature's PARENT the referenced node, which is what node-saml's
 * enveloped-only guard (`xml.js:93`) demands. It is also the only action that
 * works for every fixture variant: an <Issuer>-anchored `action: 'after'`
 * throws when a fixture omits <Issuer>.
 */
export function signAssertion(xml: string, id: string, o: SignOptions = {}): string {
  const target = `//*[@ID='${id}']`;
  const c14n = o.c14n ?? C14N.exclusive;
  const sig = new SignedXml({
    privateKey: o.privateKey ?? IDP_PRIVATE_KEY_PEM,
    signatureAlgorithm: o.sigAlg ?? SIG_ALG.rsaSha256,
    canonicalizationAlgorithm: c14n,
  });
  sig.addReference({
    xpath: target,
    transforms: [ENVELOPED, c14n],
    digestAlgorithm: o.digAlg ?? DIGEST_ALG.sha256,
  });
  sig.computeSignature(xml, { location: { reference: target, action: 'prepend' } });
  return sig.getSignedXml();
}

/**
 * A decoy <ds:Signature> declaring STRONG algorithms and referencing the real
 * assertion ID, carrying junk DigestValue/SignatureValue.
 *
 * node-saml never verifies it — it only searches direct children of <Response>
 * and <Assertion> — so it costs an attacker nothing, and <samlp:Extensions>
 * precedes <Assertion> in schema order so it wins any document-order search.
 */
export function decoySignature(assertionId = DEFAULT_ASSERTION_ID): string {
  return (
    `<ds:Signature xmlns:ds="${DS_NS}"><ds:SignedInfo>` +
    `<ds:CanonicalizationMethod Algorithm="${C14N.exclusive}"/>` +
    `<ds:SignatureMethod Algorithm="${SIG_ALG.rsaSha256}"/>` +
    `<ds:Reference URI="#${assertionId}"><ds:Transforms>` +
    `<ds:Transform Algorithm="${ENVELOPED}"/>` +
    `<ds:Transform Algorithm="${C14N.exclusive}"/>` +
    `</ds:Transforms><ds:DigestMethod Algorithm="${DIGEST_ALG.sha256}"/>` +
    `<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>` +
    `<ds:SignatureValue>BBBB</ds:SignatureValue></ds:Signature>`
  );
}

/**
 * Plant a decoy algorithm declaration INSIDE the real `<ds:Signature>`, before
 * `<ds:SignedInfo>`, in a foreign namespace (H-1).
 *
 * This is the attacker-reachable shape and nothing here is protected by
 * cryptography: `<ds:SignatureValue>` covers `canon(SignedInfo)` only, and the
 * enveloped-signature transform strips the entire `<ds:Signature>` subtree from
 * the assertion digest — so an attacker can add this to a genuinely signed
 * response and neither the signature nor the digest changes.
 *
 * `xml-crypto` resolves the algorithm it VERIFIES WITH by
 * `.//*[local-name(.)='SignatureMethod']/@Algorithm` over the whole signature
 * subtree, namespace-agnostic, first in document order (`signed-xml.js:462`,
 * `:469`) — so it reads this decoy. The module's own pin read
 * `ds:SignedInfo/ds:SignatureMethod`. Two selectors, one document, different
 * answers: the pin could report a strong algorithm while a weak one ran.
 *
 * A FOREIGN namespace prefix is required: node-saml rejects a signature with
 * more than two ds-namespaced `<Transform>` descendants (`xml.js:63`), and
 * ds-namespaced decoys would also collide with our own cardinality checks
 * rather than exercising the cross-library divergence this models.
 *
 * @param localName the element to shadow — `SignatureMethod` or
 *                  `CanonicalizationMethod`.
 */
export function withAlgorithmDecoyInSignature(
  signedXml: string,
  localName: 'SignatureMethod' | 'CanonicalizationMethod',
  algorithm: string
): string {
  const decoy =
    `<ds:Object xmlns:ds="${DS_NS}"><x:${localName} xmlns:x="urn:decoy:test" ` +
    `Algorithm="${algorithm}"/></ds:Object>`;
  const signature = signatureElementOf(signedXml);
  // Inserted as the FIRST child of <Signature>, ahead of <SignedInfo>, so it
  // wins xml-crypto's document-order descendant search.
  const opening = signature.slice(0, signature.indexOf('>') + 1);
  return signedXml.replace(signature, signature.replace(opening, `${opening}${decoy}`));
}

/**
 * Append a well-formedness WARNING-class malformation to an already-signed
 * response: `count` attributes with unquoted values (NEW-1).
 *
 * `@xmldom/xmldom` classifies an unquoted attribute value as a *warning*, not an
 * error, so node-saml's strict parse does NOT reject it and the document
 * survives all the way to signature verification — where `xml-crypto`'s
 * unconfigured `DOMParser` writes one `console.warn` line per malformation,
 * each carrying the attacker's chosen attribute name verbatim. Executed before
 * the fix: 1 / 50 / 400 attributes produced 1 / 50 / 400 stderr writes on a
 * response that AUTHENTICATED SUCCESSFULLY.
 *
 * The marker name is attacker-chosen on purpose — it is the needle a log-hygiene
 * test looks for.
 */
export function withUnquotedAttributes(signedXml: string, count = 1, marker = 'ATTACKERMARKER'): string {
  const attrs = Array.from({ length: count }, (_, i) => `${marker}${i}=UNQUOTED`).join(' ');
  return signedXml.replace('</samlp:Response>', `<junk ${attrs}/></samlp:Response>`);
}

/** The POST body the ACS endpoint receives. */
export function toPostBody(xml: string): string {
  return Buffer.from(xml).toString('base64');
}

/** A correctly signed, in-window, fully valid response. */
export function validSignedResponse(o: ResponseOverrides = {}): string {
  return signAssertion(buildResponse(o), o.assertionId ?? DEFAULT_ASSERTION_ID);
}

/**
 * Sign the `<samlp:Response>` envelope itself.
 *
 * `saml.js:562` sets `verifiedXml = responseVerifiedXml || assertionVerifiedXml`,
 * so when an envelope signature is present it — not the assertion signature —
 * decides which bytes are consumed. Used by the §B.15.2 case: a weak envelope
 * over a strong assertion.
 */
export function signEnvelope(xml: string, o: SignOptions = {}, responseId = '_resp-0001'): string {
  return signAssertion(xml, responseId, o);
}

/**
 * xml-crypto emits `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` with
 * no prefix, so tests that relocate or duplicate the signature match on the
 * unprefixed name.
 */
const SIGNATURE_RE = /<Signature[\s\S]*?<\/Signature>/;

/** The signature element of a signed document, verbatim. */
export function signatureElementOf(signedXml: string): string {
  const match = signedXml.match(SIGNATURE_RE);
  if (match === null) throw new Error('fixture: no <Signature> element found');
  return match[0];
}

/** The `<saml:Assertion>` element of a document, verbatim. */
export function assertionElementOf(xml: string): string {
  const start = xml.indexOf('<saml:Assertion');
  const end = xml.indexOf('</saml:Assertion>');
  if (start < 0 || end < 0) throw new Error('fixture: no <saml:Assertion> element found');
  return xml.substring(start, end + '</saml:Assertion>'.length);
}

// ---------------------------------------------------------------------------
// XML Signature Wrapping payloads (TEST-003)
//
// Each shape trips a DIFFERENT node-saml guard. Testing one shape only would let
// a regression in the other guards through, which is why §B.3 lists all of them.
// Every builder injects its decoy AFTER signing, so the signed byte range is
// untouched and the payload is exactly what an attacker could actually produce
// from a legitimately signed assertion.
// ---------------------------------------------------------------------------

/** An unsigned attacker assertion appended as a sibling. Guard: "multiple assertions". */
export function xswSiblingAssertion(email = 'admin@example.test'): string {
  const sibling =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xsw-sibling" ` +
    `Version="2.0" IssueInstant="${iso(0)}">` +
    `<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
    `<saml:Subject><saml:NameID>${email}</saml:NameID></saml:Subject>` +
    `</saml:Assertion>`;
  return validSignedResponse().replace('</samlp:Response>', `${sibling}</samlp:Response>`);
}

/**
 * The signature relocated to be a direct child of `<Response>` while its
 * `Reference/@URI` still names the assertion.
 * Guard: "Referenced node does not refer to it's parent element".
 */
export function xswRelocatedSignature(): string {
  const signed = validSignedResponse();
  const signature = signatureElementOf(signed);
  return signed.replace(signature, '').replace('<samlp:Status>', `${signature}<samlp:Status>`);
}

/**
 * An unsigned copy of the assertion, re-using the SAME `ID`, planted in
 * `<samlp:Extensions>`. Guard: "ID cannot refer to more than one element".
 */
export function xswDuplicateIdInExtensions(email = 'admin@example.test'): string {
  const signed = validSignedResponse();
  const copy = assertionElementOf(signed)
    .replace(signatureElementOf(signed), '')
    .replace(new RegExp(DEFAULT_EMAIL, 'g'), email);
  return signed.replace('<samlp:Status>', `<samlp:Extensions>${copy}</samlp:Extensions><samlp:Status>`);
}

/**
 * The genuinely signed assertion buried inside `<saml:Advice>` of an unsigned
 * attacker assertion sitting at the normal position.
 * Guard: node-saml only searches direct children of `assertions[0]`, so the real
 * signature is never found — "Invalid signature".
 */
export function xswAdviceNested(email = 'admin@example.test'): string {
  const outer =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xsw-advice" ` +
    `Version="2.0" IssueInstant="${iso(0)}">` +
    `<saml:Advice>${assertionElementOf(validSignedResponse())}</saml:Advice>` +
    `<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
    `<saml:Subject><saml:NameID>${email}</saml:NameID></saml:Subject>` +
    `</saml:Assertion>`;
  return buildResponse().replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, outer);
}

/** The same signature present twice on the assertion. Guard: "Too many signatures". */
export function xswDoubleSignature(): string {
  const signed = validSignedResponse();
  const signature = signatureElementOf(signed);
  return signed.replace(signature, signature + signature);
}

/**
 * DOCTYPE casings for TEST-016.
 *
 * Applied AFTER signing so the response underneath stays validly signed — the
 * point of the test is that a DTD rides along on an otherwise acceptable
 * document. XML 1.0 requires the uppercase keyword, but `@xmldom/xmldom` 0.8.13
 * parses all four of these, and node-saml accepts every one of them, so a filter
 * written as `includes('<!DOCTYPE')` is evaded by three of the four.
 */
export const DOCTYPE_CASINGS = [
  '<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
  '<!doctype samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
  '<!DoCtYpE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
  '<!  DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
] as const;

/** Prepend a DTD to an already-signed response. */
export function withDoctype(signedXml: string, doctype: string): string {
  return doctype + signedXml;
}

/**
 * A body carrying 30 undeclared entity references. `@xmldom/xmldom` does not
 * throw on these: it writes 30 lines of attacker-chosen text and position data
 * to `console.error` and returns a partial document, and `try`/`catch` cannot
 * intercept any of it. Both the text and the call count are attacker-controlled,
 * which makes it a log-volume amplifier on an unauthenticated endpoint.
 */
export function malformedEntityBody(count = 30): string {
  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp-0001" ` +
    `InResponseTo="${DEFAULT_REQUEST_ID}">${'&evilentity;'.repeat(count)}</samlp:Response>`
  );
}
