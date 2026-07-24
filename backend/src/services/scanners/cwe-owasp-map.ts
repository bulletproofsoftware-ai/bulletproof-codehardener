/**
 * Maps CWE IDs to OWASP 2021 Top 10 categories.
 * Used by scanner adapters to derive OWASP categories from CWE IDs
 * instead of hardcoding them.
 *
 * Reference: https://cwe.mitre.org/data/definitions/
 * Reference: https://owasp.org/Top10/
 */

// OWASP 2021 Top 10 category constants
const A01 = 'A01:2021-Broken Access Control';
const A02 = 'A02:2021-Cryptographic Failures';
const A03 = 'A03:2021-Injection';
const A04 = 'A04:2021-Insecure Design';
const A05 = 'A05:2021-Security Misconfiguration';
const A06 = 'A06:2021-Vulnerable and Outdated Components';
const A07 = 'A07:2021-Identification and Authentication Failures';
const A08 = 'A08:2021-Software and Data Integrity Failures';
const A09 = 'A09:2021-Security Logging and Monitoring Failures';
const A10 = 'A10:2021-Server-Side Request Forgery';

/**
 * CWE ID (numeric) to OWASP 2021 Top 10 category mapping.
 * Covers 100+ of the most commonly reported CWEs, with emphasis on
 * vulnerabilities frequently introduced by AI code generators.
 *
 * Mappings are based on the official OWASP CWE mapping:
 * https://owasp.org/Top10/A01_2021-Broken_Access_Control/
 */
const CWE_OWASP_MAP: Record<number, string> = {
  // ── A01:2021-Broken Access Control ──────────────────────────────────
  22: A01,   // Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
  23: A01,   // Relative Path Traversal
  35: A01,   // Path Traversal: '.../...//'
  36: A01,   // Absolute Path Traversal
  59: A01,   // Improper Link Resolution Before File Access (Link Following)
  200: A01,  // Exposure of Sensitive Information to an Unauthorized Actor
  201: A01,  // Insertion of Sensitive Information Into Sent Data
  219: A01,  // Storage of File with Sensitive Data Under Web Root
  264: A01,  // Permissions, Privileges, and Access Controls (deprecated but still reported)
  275: A01,  // Permission Issues
  276: A01,  // Incorrect Default Permissions
  281: A01,  // Improper Preservation of Permissions
  284: A01,  // Improper Access Control
  285: A01,  // Improper Authorization
  352: A01,  // Cross-Site Request Forgery (CSRF)
  359: A01,  // Exposure of Private Personal Information to an Unauthorized Actor
  377: A01,  // Insecure Temporary File
  402: A01,  // Transmission of Private Resources into a New Sphere
  425: A01,  // Direct Request (Forced Browsing)
  538: A01,  // Insertion of Sensitive Information into Externally-Accessible File
  540: A01,  // Inclusion of Sensitive Information in Source Code
  548: A01,  // Exposure of Information Through Directory Listing
  552: A01,  // Files or Directories Accessible to External Parties
  566: A01,  // Authorization Bypass Through User-Controlled SQL Primary Key
  601: A01,  // URL Redirection to Untrusted Site (Open Redirect)
  639: A01,  // Authorization Bypass Through User-Controlled Key (IDOR)
  651: A01,  // Exposure of WSDL File Containing Sensitive Information
  668: A01,  // Exposure of Resource to Wrong Sphere
  706: A01,  // Use of Incorrectly-Resolved Name or Reference
  732: A01,  // Incorrect Permission Assignment for Critical Resource
  862: A01,  // Missing Authorization
  863: A01,  // Incorrect Authorization
  913: A01,  // Improper Control of Dynamically-Managed Code Resources
  922: A01,  // Insecure Storage of Sensitive Information
  1021: A01, // Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
  1275: A01, // Sensitive Cookie with Improper SameSite Attribute

  // ── A02:2021-Cryptographic Failures ──────────────────────────────────
  261: A02,  // Weak Encoding for Password
  296: A02,  // Improper Following of a Certificate's Chain of Trust
  310: A02,  // Cryptographic Issues
  319: A02,  // Cleartext Transmission of Sensitive Information
  320: A02,  // Key Management Errors
  321: A02,  // Use of Hard-coded Cryptographic Key
  322: A02,  // Key Exchange without Entity Authentication
  323: A02,  // Reusing a Nonce, Key Pair in Encryption
  324: A02,  // Use of a Key Past its Expiration Date
  325: A02,  // Missing Cryptographic Step
  326: A02,  // Inadequate Encryption Strength
  327: A02,  // Use of a Broken or Risky Cryptographic Algorithm
  328: A02,  // Use of Weak Hash
  329: A02,  // Generation of Predictable IV with CBC Mode
  330: A02,  // Use of Insufficiently Random Values
  331: A02,  // Insufficient Entropy
  334: A02,  // Small Space of Random Values
  335: A02,  // Incorrect Usage of Seeds in Pseudo-Random Number Generator
  338: A02,  // Use of Cryptographically Weak Pseudo-Random Number Generator
  340: A02,  // Generation of Predictable Numbers or Identifiers
  347: A02,  // Improper Verification of Cryptographic Signature
  523: A02,  // Unprotected Transport of Credentials
  614: A02,  // Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  757: A02,  // Selection of Less-Secure Algorithm During Negotiation
  759: A02,  // Use of a One-Way Hash without a Salt
  760: A02,  // Use of a One-Way Hash with a Predictable Salt
  780: A02,  // Use of RSA Algorithm without OAEP
  818: A02,  // Insufficient Transport Layer Protection (deprecated but reported)
  916: A02,  // Use of Password Hash With Insufficient Computational Effort

  // ── A03:2021-Injection ──────────────────────────────────────────────
  20: A03,   // Improper Input Validation
  74: A03,   // Improper Neutralization of Special Elements in Output (Injection)
  75: A03,   // Failure to Sanitize Special Elements into a Different Plane
  77: A03,   // Command Injection
  78: A03,   // Improper Neutralization of Special Elements used in an OS Command
  79: A03,   // Improper Neutralization of Input During Web Page Generation (XSS)
  80: A03,   // Improper Neutralization of Script-Related HTML Tags
  83: A03,   // Improper Neutralization of Script in Attributes
  87: A03,   // Improper Neutralization of Alternate XSS Syntax
  89: A03,   // SQL Injection
  90: A03,   // LDAP Injection
  91: A03,   // XML Injection
  93: A03,   // Improper Neutralization of CRLF Sequences (CRLF Injection)
  94: A03,   // Improper Control of Generation of Code (Code Injection)
  95: A03,   // Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)
  96: A03,   // Improper Neutralization of Directives in Statically Saved Code
  97: A03,   // Improper Neutralization of Server-Side Includes (SSI)
  98: A03,   // Improper Control of Filename for Include/Require Statement (LFI/RFI)
  99: A03,   // Improper Control of Resource Identifiers (Resource Injection)
  113: A03,  // Improper Neutralization of CRLF Sequences in HTTP Headers
  116: A03,  // Improper Encoding or Escaping of Output
  117: A03,  // Improper Output Neutralization for Logs (Log Injection)
  138: A03,  // Improper Neutralization of Special Elements
  176: A03,  // Improper Handling of Unicode Encoding
  184: A03,  // Incomplete List of Disallowed Inputs
  470: A03,  // Use of Externally-Controlled Input to Select Classes or Code
  471: A03,  // Modification of Assumed-Immutable Data
  564: A03,  // SQL Injection: Hibernate
  643: A03,  // Improper Neutralization of Data within XPath Expressions
  644: A03,  // Improper Neutralization of HTTP Headers for Scripting Syntax
  652: A03,  // Improper Neutralization of Data within XQuery Expressions
  917: A03,  // Improper Neutralization of Special Elements used in an Expression Language Statement

  // ── A04:2021-Insecure Design ────────────────────────────────────────
  73: A04,   // External Control of File Name or Path
  183: A04,  // Permissive List of Allowed Inputs
  209: A04,  // Generation of Error Message Containing Sensitive Information
  213: A04,  // Exposure of Sensitive Information Due to Incompatible Policies
  235: A04,  // Improper Handling of Extra Parameters
  256: A04,  // Plaintext Storage of a Password
  257: A04,  // Storing Passwords in a Recoverable Format
  266: A04,  // Incorrect Privilege Assignment
  269: A04,  // Improper Privilege Management
  280: A04,  // Improper Handling of Insufficient Permissions or Privileges
  311: A04,  // Missing Encryption of Sensitive Data
  312: A04,  // Cleartext Storage of Sensitive Information
  313: A04,  // Cleartext Storage in a File or on Disk
  316: A04,  // Cleartext Storage of Sensitive Information in Memory
  419: A04,  // Unprotected Primary Channel
  430: A04,  // Deployment of Wrong Handler
  434: A04,  // Unrestricted Upload of File with Dangerous Type
  444: A04,  // HTTP Request/Response Smuggling
  451: A04,  // User Interface (UI) Misrepresentation of Critical Information
  472: A04,  // External Control of Assumed-Immutable Web Parameter
  501: A04,  // Trust Boundary Violation
  522: A04,  // Insufficiently Protected Credentials
  602: A04,  // Client-Side Enforcement of Server-Side Security
  // CWE-640 mapped under A07 (primary: Authentication Failures)
  770: A04,  // Allocation of Resources Without Limits or Throttling
  841: A04,  // Improper Enforcement of Behavioral Workflow
  927: A04,  // Use of Implicit Intent for Sensitive Communication

  // ── A05:2021-Security Misconfiguration ──────────────────────────────
  2: A05,    // Environment
  11: A05,   // ASP.NET Misconfiguration
  13: A05,   // ASP.NET Misconfiguration: Password in Configuration File
  15: A05,   // External Control of System or Configuration Setting
  16: A05,   // Configuration
  260: A05,  // Password in Configuration File
  315: A05,  // Cleartext Storage of Sensitive Information in a Cookie
  520: A05,  // .NET Misconfiguration: Use of Impersonation
  526: A05,  // Exposure of Sensitive Information Through Environmental Variables
  537: A05,  // Exposure of Information Through Java Runtime Error Message
  541: A05,  // Inclusion of Sensitive Information in an Include File
  547: A05,  // Use of Hard-coded, Security-relevant Constants
  611: A05,  // Improper Restriction of XML External Entity Reference (XXE)
  // CWE-614 mapped under A02 (primary: Cryptographic Failures)
  756: A05,  // Missing Custom Error Page
  776: A05,  // Improper Restriction of Recursive Entity References in DTDs (XML Bomb)
  942: A05,  // Permissive Cross-domain Policy with Untrusted Domains
  1004: A05, // Sensitive Cookie Without 'HttpOnly' Flag
  1032: A05, // OWASP Top Ten 2017 A6 - Security Misconfiguration

  // ── A06:2021-Vulnerable and Outdated Components ─────────────────────
  937: A06,  // Using Components with Known Vulnerabilities
  1035: A06, // OWASP Top Ten 2017 A9 - Using Components with Known Vulnerabilities
  1104: A06, // Use of Unmaintained Third-Party Components

  // ── A07:2021-Identification and Authentication Failures ─────────────
  255: A07,  // Credentials Management Errors
  259: A07,  // Use of Hard-coded Password
  262: A07,  // Not Using Password Aging
  263: A07,  // Password Aging with Long Expiration
  287: A07,  // Improper Authentication
  288: A07,  // Authentication Bypass Using an Alternate Path or Channel
  290: A07,  // Authentication Bypass by Spoofing
  294: A07,  // Authentication Bypass by Capture-replay
  295: A07,  // Improper Certificate Validation
  297: A07,  // Improper Validation of Certificate with Host Mismatch
  300: A07,  // Channel Accessible by Non-Endpoint
  302: A07,  // Authentication Bypass by Assumed-Immutable Data
  304: A07,  // Missing Critical Step in Authentication
  306: A07,  // Missing Authentication for Critical Function
  307: A07,  // Improper Restriction of Excessive Authentication Attempts
  346: A07,  // Origin Validation Error
  384: A07,  // Session Fixation
  521: A07,  // Weak Password Requirements
  613: A07,  // Insufficient Session Expiration
  620: A07,  // Unverified Password Change
  640: A07,  // Weak Password Recovery Mechanism
  798: A07,  // Use of Hard-coded Credentials
  940: A07,  // Improper Verification of Source of a Communication Channel

  // ── A08:2021-Software and Data Integrity Failures ───────────────────
  345: A08,  // Insufficient Verification of Data Authenticity
  353: A08,  // Missing Support for Integrity Check
  426: A08,  // Untrusted Search Path
  427: A08,  // Unquoted Search Path or Element
  428: A08,  // Unquoted Search Path
  502: A08,  // Deserialization of Untrusted Data
  565: A08,  // Reliance on Cookies without Validation and Integrity Checking
  784: A08,  // Reliance on Cookies without Validation in Security Decision
  829: A08,  // Inclusion of Functionality from Untrusted Control Sphere
  830: A08,  // Inclusion of Web Functionality from an Untrusted Source
  915: A08,  // Improperly Controlled Modification of Dynamically-Determined Object Attributes

  // ── A09:2021-Security Logging and Monitoring Failures ───────────────
  // CWE-117 mapped under A03 (primary: Injection)
  223: A09,  // Omission of Security-relevant Information
  532: A09,  // Insertion of Sensitive Information into Log File
  778: A09,  // Insufficient Logging
  779: A09,  // Logging of Excessive Data

  // ── A10:2021-Server-Side Request Forgery ────────────────────────────
  918: A10,  // Server-Side Request Forgery (SSRF)

  // ── Additional common CWEs mapped to best-fit categories ────────────
  119: A03,  // Improper Restriction of Operations within the Bounds of a Memory Buffer
  120: A03,  // Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
  125: A03,  // Out-of-bounds Read
  129: A03,  // Improper Validation of Array Index
  134: A03,  // Use of Externally-Controlled Format String
  190: A03,  // Integer Overflow or Wraparound
  191: A03,  // Integer Underflow
  250: A04,  // Execution with Unnecessary Privileges
  362: A04,  // Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
  369: A04,  // Divide By Zero
  400: A04,  // Uncontrolled Resource Consumption
  415: A03,  // Double Free
  416: A03,  // Use After Free
  476: A04,  // NULL Pointer Dereference
  477: A04,  // Use of Obsolete Function
  506: A08,  // Embedded Malicious Code
  676: A04,  // Use of Potentially Dangerous Function
  681: A04,  // Incorrect Conversion between Numeric Types
  693: A04,  // Protection Mechanism Failure
  704: A04,  // Incorrect Type Conversion or Cast
  754: A04,  // Improper Check for Unusual or Exceptional Conditions
  787: A03,  // Out-of-bounds Write
  789: A04,  // Memory Allocation with Excessive Size Value
  835: A04,  // Loop with Unreachable Exit Condition (Infinite Loop)
  843: A03,  // Access of Resource Using Incompatible Type (Type Confusion)
  1333: A04, // Inefficient Regular Expression Complexity (ReDoS)
};

/**
 * Maps a CWE ID to its corresponding OWASP 2021 Top 10 category.
 *
 * Accepts CWE IDs in various formats:
 *   - "CWE-79"
 *   - "cwe-79"
 *   - "79"
 *   - 79
 *
 * @param cweId - The CWE identifier (string or null)
 * @returns The OWASP 2021 Top 10 category string, or null if not mapped
 */
export function cweToOwasp(cweId: string | null): string | null {
  if (!cweId) return null;

  const match = cweId.match(/(\d+)/);
  if (!match) return null;

  const id = parseInt(match[1], 10);
  return CWE_OWASP_MAP[id] ?? null;
}

/**
 * Returns all CWE IDs mapped to a given OWASP category.
 * Useful for reporting and coverage analysis.
 */
export function owaspToCwes(owaspCategory: string): number[] {
  return Object.entries(CWE_OWASP_MAP)
    .filter(([, category]) => category === owaspCategory)
    .map(([id]) => parseInt(id, 10))
    .sort((a, b) => a - b);
}

/**
 * Returns the full OWASP 2021 Top 10 category list.
 */
export const OWASP_CATEGORIES = [
  A01, A02, A03, A04, A05, A06, A07, A08, A09, A10,
] as const;

export type OwaspCategory = typeof OWASP_CATEGORIES[number];
