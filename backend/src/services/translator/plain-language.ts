import type { Severity } from '../../types/index.js';

interface TranslatedFinding {
  titleSimple: string;
  descriptionSimple: string;
  actionRequired: string;
  riskExplanation: string;
}

// CWE to plain language mapping
// Covers 50+ CWEs with emphasis on vulnerabilities commonly introduced by AI code generators
const CWE_EXPLANATIONS: Record<string, string> = {
  // -- Injection family --
  'CWE-20': 'This vulnerability means user input is not properly checked before being used. An attacker could send unexpected data to crash your application or bypass security controls. AI-generated code frequently skips input validation because generators focus on the "happy path."',
  'CWE-22': 'This vulnerability allows an attacker to access files and directories outside the intended folder by manipulating file paths (e.g., using "../"). An attacker could read sensitive configuration files, source code, or system files. AI code generators often build file-handling code without restricting path traversal.',
  'CWE-74': 'This vulnerability allows special characters in user input to be interpreted as commands or control sequences. An attacker could inject malicious commands into your application.',
  'CWE-77': 'This vulnerability allows an attacker to inject arbitrary commands that your application will execute. An attacker could run any command on your server, potentially taking full control. AI assistants frequently construct command strings by concatenating user input without sanitization.',
  'CWE-78': 'This vulnerability allows an attacker to inject operating system commands through your application. An attacker could execute arbitrary commands on the server, install malware, or pivot to other systems. AI-generated code commonly uses shell commands with unsanitized input for file operations and system tasks.',
  'CWE-79': 'This vulnerability (Cross-Site Scripting / XSS) allows attackers to inject malicious scripts into your web pages. An attacker could steal user session cookies, redirect users to phishing sites, or deface your application. AI code generators frequently output user data directly into HTML without encoding.',
  'CWE-89': 'This vulnerability (SQL Injection) allows attackers to manipulate your database queries by injecting SQL code through user input. An attacker could read, modify, or delete your entire database. AI-generated code often builds SQL strings with concatenation instead of parameterized queries.',
  'CWE-90': 'This vulnerability allows attackers to inject LDAP queries to bypass authentication or extract directory information. An attacker could enumerate users or bypass login controls.',
  'CWE-94': 'This vulnerability allows attackers to inject and execute arbitrary code in your application. An attacker could take complete control of the server, access all data, and pivot to other systems. AI code generators sometimes use dynamic code execution with user-controlled input.',
  'CWE-95': 'This vulnerability allows attackers to inject code into dynamically evaluated expressions. An attacker could execute arbitrary code within your application context.',
  'CWE-98': 'This vulnerability allows attackers to control which files your application includes or requires. An attacker could include malicious remote files or read sensitive local files.',
  'CWE-113': 'This vulnerability allows attackers to inject CRLF characters into HTTP headers. An attacker could perform response splitting, session fixation, or cross-site scripting attacks.',
  'CWE-116': 'This vulnerability means output is not properly encoded or escaped before being sent to a downstream component. An attacker could inject malicious content that gets interpreted as code or commands. AI-generated code often fails to apply context-appropriate output encoding.',
  'CWE-117': 'This vulnerability allows attackers to inject false entries into your application logs. An attacker could forge log entries to cover their tracks or mislead incident responders.',

  // -- Cryptographic failures --
  'CWE-259': 'This vulnerability means passwords are hardcoded directly in the source code. An attacker who gains access to the code instantly has the credentials.',
  'CWE-261': 'This vulnerability means passwords are stored using weak encoding (like Base64) rather than proper hashing. An attacker could trivially reverse the encoding to recover passwords.',
  'CWE-310': 'This vulnerability involves general cryptographic weaknesses in your code. An attacker could break the encryption to access protected data.',
  'CWE-319': 'This vulnerability means sensitive data is transmitted over unencrypted channels (HTTP instead of HTTPS). An attacker on the same network could intercept and read the data in transit.',
  'CWE-326': 'This vulnerability means encryption is used but the key size or algorithm strength is too weak. An attacker could break the encryption using modern computing resources. AI code generators sometimes default to outdated key sizes like 1024-bit RSA.',
  'CWE-327': 'This vulnerability means your code uses outdated or broken cryptographic algorithms (like MD5, SHA1, DES, or RC4). An attacker could exploit known weaknesses in these algorithms to decrypt data. AI-generated code frequently suggests deprecated algorithms.',
  'CWE-328': 'This vulnerability means a weak hash function is used where a strong one is needed. An attacker could find hash collisions or reverse the hash to recover the original data.',
  'CWE-330': 'This vulnerability means your code generates random values that are predictable. An attacker could guess tokens, session IDs, or cryptographic keys. AI code generators frequently use Math.random() or similar non-cryptographic random sources for security-sensitive values.',
  'CWE-338': 'This vulnerability means a non-cryptographic random number generator is used for security purposes. An attacker could predict generated values like session tokens or password reset codes.',

  // -- Access control --
  'CWE-200': 'This vulnerability exposes sensitive information to users who should not have access to it. An attacker could learn system internals, credentials, or personal data from error messages, debug output, or improperly protected endpoints. AI-generated code often returns full stack traces or detailed error information to clients.',
  'CWE-250': 'This vulnerability means your application runs with more privileges than it needs. An attacker who compromises the application gains those excess privileges, expanding the blast radius. AI-generated Docker and deployment code often runs as root by default.',
  'CWE-264': 'This vulnerability involves improper handling of permissions and privileges. An attacker could access resources or perform actions that should be restricted.',
  'CWE-276': 'This vulnerability means files or resources are created with overly permissive default access rights. An attacker could read or modify files they should not have access to.',
  'CWE-284': 'This vulnerability means access controls are not properly enforced. An attacker could access restricted functionality or data by bypassing or exploiting weak authorization checks. AI-generated APIs frequently lack proper access control middleware.',
  'CWE-285': 'This vulnerability means your application does not properly verify whether a user is authorized to perform a specific action. An attacker could perform privileged operations by manipulating requests. AI code generators often implement authentication but skip fine-grained authorization checks.',
  'CWE-352': 'This vulnerability (Cross-Site Request Forgery) allows attackers to trick authenticated users into performing unwanted actions. An attacker could transfer funds, change passwords, or modify data by luring a user to a malicious page. AI-generated forms and APIs often omit CSRF token validation.',
  'CWE-359': 'This vulnerability exposes private personal information to unauthorized parties. An attacker could harvest personal data like email addresses, phone numbers, or financial details.',
  'CWE-377': 'This vulnerability means temporary files are created insecurely, with predictable names or in shared directories. An attacker could read sensitive data from or inject malicious content via these temporary files. AI code generators often use predictable paths like /tmp/output.txt.',
  'CWE-425': 'This vulnerability means users can access pages or functionality by directly entering URLs, bypassing intended navigation flow and access controls.',
  'CWE-601': 'This vulnerability allows attackers to redirect users from your site to a malicious website. An attacker could phish credentials or distribute malware by abusing your trusted domain. AI-generated redirect logic often fails to validate target URLs.',
  'CWE-639': 'This vulnerability allows attackers to access other users\' data by modifying an identifier (like a user ID) in the request. An attacker could read or modify any user\'s data by guessing or enumerating IDs.',
  'CWE-732': 'This vulnerability means critical resources like configuration files or executables have incorrect permissions. An attacker could read secrets from config files or replace executables with malicious versions.',
  'CWE-862': 'This vulnerability means critical functions have no authorization check at all. An attacker could access administrative or privileged functionality simply by calling the endpoint. AI-generated backends frequently expose endpoints without any authorization middleware.',
  'CWE-863': 'This vulnerability means authorization checks exist but are implemented incorrectly. An attacker could bypass them to access resources belonging to other users or perform unauthorized actions.',
  'CWE-1021': 'This vulnerability allows your application\'s pages to be embedded in iframes on malicious sites (clickjacking). An attacker could trick users into clicking hidden buttons or links by overlaying your UI with a deceptive page.',

  // -- Authentication --
  'CWE-287': 'This vulnerability means authentication mechanisms are improperly implemented. An attacker could bypass login controls and access protected resources without valid credentials.',
  'CWE-295': 'This vulnerability means your application does not properly verify SSL/TLS certificates. An attacker could perform man-in-the-middle attacks to intercept encrypted communications. AI-generated code often disables certificate verification for convenience during development and the setting persists to production.',
  'CWE-306': 'This vulnerability means a critical function has no authentication requirement at all. An attacker could access sensitive operations like admin panels or data exports without logging in. AI code generators frequently create API endpoints without any authentication middleware.',
  'CWE-307': 'This vulnerability means your application does not limit failed login attempts. An attacker could brute-force passwords by trying unlimited combinations.',
  'CWE-384': 'This vulnerability allows an attacker to fixate a user\'s session identifier, then hijack the session after the user logs in.',
  'CWE-521': 'This vulnerability means your application accepts weak passwords that are easy to guess or brute-force. An attacker could gain access to accounts through dictionary attacks or credential stuffing. AI-generated authentication code often omits password complexity requirements.',
  'CWE-613': 'This vulnerability means user sessions do not expire or take too long to expire. An attacker who obtains a session token has an extended window to use it.',
  'CWE-640': 'This vulnerability means the password recovery mechanism is weak or exploitable. An attacker could reset other users\' passwords by exploiting predictable reset tokens, security questions, or missing rate limits.',
  'CWE-798': 'This vulnerability means credentials (passwords, API keys, tokens) are embedded directly in the source code. An attacker who accesses your code repository instantly has valid credentials. AI code generators frequently hardcode example credentials that end up in production.',

  // -- Data integrity --
  'CWE-345': 'This vulnerability means your application does not verify the authenticity of received data. An attacker could tamper with data in transit or inject forged data.',
  'CWE-434': 'This vulnerability allows users to upload files without proper restrictions on type, size, or content. An attacker could upload executable scripts (like web shells) to take control of your server. AI code generators often implement basic file upload without validating file types or content.',
  'CWE-502': 'This vulnerability allows attackers to execute code by sending crafted serialized data to your application. An attacker could achieve remote code execution by manipulating deserialized objects. AI-generated code sometimes deserializes data from untrusted sources without validation.',
  'CWE-565': 'This vulnerability means your application relies on cookie values without verifying their integrity. An attacker could modify cookies to bypass security controls or impersonate other users.',
  'CWE-829': 'This vulnerability means your application includes code or functionality from untrusted external sources. An attacker could compromise the external source to inject malicious code into your application. AI-generated code frequently includes third-party scripts from CDNs without integrity checks.',

  // -- Security misconfiguration --
  'CWE-209': 'This vulnerability means error messages reveal sensitive internal details like stack traces, file paths, or database queries. An attacker could use this information to plan targeted attacks.',
  'CWE-315': 'This vulnerability means sensitive information is stored in cookies without encryption. An attacker could read the cookie data to obtain secrets or personal information.',
  'CWE-526': 'This vulnerability means sensitive information is exposed through environment variables that may be accessible via debug pages, error messages, or process listings.',
  'CWE-611': 'This vulnerability (XML External Entity / XXE) allows attackers to include external entities in XML input. An attacker could read sensitive files from the server, perform SSRF attacks, or cause denial of service. AI code generators often use XML parsers with default (insecure) settings.',
  'CWE-614': 'This vulnerability means cookies containing sensitive data are sent over unencrypted HTTP connections. An attacker on the same network could intercept and steal session cookies or authentication tokens.',
  'CWE-776': 'This vulnerability (XML Bomb) allows attackers to cause denial of service by sending XML with deeply nested entity references. An attacker could crash your server or exhaust its memory with a small payload.',
  'CWE-942': 'This vulnerability means your application allows cross-origin requests from untrusted domains. An attacker could make requests to your API from a malicious website, accessing data on behalf of your users.',
  'CWE-1004': 'This vulnerability means cookies lack the HttpOnly flag, making them accessible to JavaScript. An attacker could steal session cookies via cross-site scripting attacks.',

  // -- Logging and monitoring --
  'CWE-532': 'This vulnerability means sensitive information (passwords, tokens, personal data) is written to log files. An attacker who accesses logs could obtain credentials or personal data. AI code generators frequently log full request bodies including sensitive fields.',
  'CWE-778': 'This vulnerability means your application does not log security-relevant events like failed logins, access control failures, or configuration changes. An attacker could operate undetected because there is no audit trail.',

  // -- SSRF --
  'CWE-918': 'This vulnerability (Server-Side Request Forgery) allows attackers to make your server send requests to arbitrary destinations. An attacker could access internal services, cloud metadata endpoints, or scan internal networks through your server. AI-generated code that fetches URLs often fails to restrict target hosts.',

  // -- Resource management --
  'CWE-119': 'This vulnerability (buffer overflow) occurs when data is written beyond the bounds of allocated memory. An attacker could crash your application or execute arbitrary code.',
  'CWE-125': 'This vulnerability allows reading data from memory locations outside intended boundaries. An attacker could extract sensitive data from memory.',
  'CWE-190': 'This vulnerability occurs when an integer calculation exceeds its maximum value and wraps around. An attacker could exploit this to cause buffer overflows or bypass security checks.',
  'CWE-400': 'This vulnerability means your application does not limit resource consumption. An attacker could exhaust CPU, memory, disk, or network resources to deny service to legitimate users. AI-generated code often omits rate limiting, request size limits, and timeout configurations.',
  'CWE-476': 'This vulnerability means your code dereferences a null pointer, causing crashes. An attacker could trigger this to cause denial of service.',
  'CWE-787': 'This vulnerability allows writing data outside the bounds of allocated memory. An attacker could corrupt data, crash the application, or execute arbitrary code.',

  // -- Additional AI-relevant CWEs --
  'CWE-362': 'This vulnerability (race condition) occurs when multiple processes or threads access shared resources without proper synchronization. An attacker could exploit timing windows to bypass security checks or corrupt data.',
  'CWE-470': 'This vulnerability allows user input to determine which classes or code modules are loaded. An attacker could load malicious code by manipulating class names or paths.',
  'CWE-501': 'This vulnerability means data crosses a trust boundary without validation. An attacker could inject untrusted data into a trusted context.',
  'CWE-693': 'This vulnerability means a security protection mechanism is missing or can be bypassed. An attacker could circumvent intended security controls.',
  'CWE-915': 'This vulnerability allows attackers to modify object properties they should not have access to (mass assignment). An attacker could set admin flags, change prices, or modify other protected fields. AI-generated code frequently binds request bodies directly to database models without filtering.',
  'CWE-1333': 'This vulnerability (Regular Expression Denial of Service / ReDoS) occurs when a poorly crafted regular expression takes exponential time on certain inputs. An attacker could send a short string that causes your server to hang. AI code generators frequently produce complex regex patterns without considering pathological inputs.',
};

// OWASP to plain language mapping
const OWASP_EXPLANATIONS: Record<string, string> = {
  'A01:2021-Broken Access Control': 'Users can access resources or perform actions they shouldn\'t be allowed to.',
  'A02:2021-Cryptographic Failures': 'Sensitive data isn\'t properly protected, making it vulnerable to exposure.',
  'A03:2021-Injection': 'User input can be interpreted as commands, allowing attackers to manipulate your system.',
  'A04:2021-Insecure Design': 'The application design has security flaws that can\'t be fixed with code alone.',
  'A05:2021-Security Misconfiguration': 'Security settings aren\'t properly configured, leaving gaps in protection.',
  'A06:2021-Vulnerable and Outdated Components': 'Using outdated libraries with known security issues.',
  'A07:2021-Identification and Authentication Failures': 'Login and identity verification has weaknesses that can be exploited.',
  'A08:2021-Software and Data Integrity Failures': 'Code or data can be modified without detection.',
  'A09:2021-Security Logging and Monitoring Failures': 'Security events aren\'t properly logged, making attacks harder to detect.',
  'A10:2021-Server-Side Request Forgery': 'Attackers can make your server send requests to unintended destinations.',
};

// Severity explanations
const SEVERITY_EXPLANATIONS: Record<Severity, string> = {
  critical: 'This issue poses an immediate and severe risk. An attacker could exploit this to gain unauthorized access, steal sensitive data, or take control of your system. Fix this immediately.',
  high: 'This is a serious security issue that should be addressed quickly. It could be exploited to compromise your application or expose sensitive information.',
  medium: 'This issue presents a moderate risk. While not immediately exploitable, it should be addressed to maintain a strong security posture.',
  low: 'This is a minor issue with limited impact. Consider fixing it when you have time, but it\'s not urgent.',
  info: 'This is informational and doesn\'t pose a direct security risk, but may indicate areas for improvement.',
};

export function translateFinding(
  title: string,
  description: string,
  severity: Severity,
  cweId: string | null,
  owaspCategory: string | null,
  scanner: string
): TranslatedFinding {
  // Simplify technical title
  const titleSimple = simplifyTitle(title, scanner);

  // Create plain language description
  let descriptionSimple = description;

  // Add CWE explanation if available
  if (cweId && CWE_EXPLANATIONS[cweId]) {
    descriptionSimple = CWE_EXPLANATIONS[cweId];
  }

  // Add OWASP explanation if available
  if (owaspCategory && OWASP_EXPLANATIONS[owaspCategory]) {
    if (!cweId) {
      descriptionSimple = OWASP_EXPLANATIONS[owaspCategory];
    }
  }

  // Get risk explanation
  const riskExplanation = SEVERITY_EXPLANATIONS[severity];

  // Generate action required
  const actionRequired = generateAction(severity, cweId, owaspCategory);

  return {
    titleSimple,
    descriptionSimple,
    actionRequired,
    riskExplanation,
  };
}

function simplifyTitle(title: string, scanner: string): string {
  // Remove CVE/CWE prefixes
  let simplified = title.replace(/^(CVE-\d{4}-\d+|CWE-\d+):\s*/i, '');

  // Remove scanner-specific prefixes
  simplified = simplified.replace(/^(trivy|gitleaks|semgrep|checkov|nuclei)[-_:]\s*/i, '');

  // Capitalize first letter
  simplified = simplified.charAt(0).toUpperCase() + simplified.slice(1);

  // Add context based on scanner
  const scannerContext: Record<string, string> = {
    trivy: 'Dependency issue',
    gitleaks: 'Secret in code',
    opengrep: 'Code pattern issue',
    checkov: 'Infrastructure issue',
    nuclei: 'Vulnerability detected',
  };

  if (simplified.length < 20 && scannerContext[scanner]) {
    simplified = `${scannerContext[scanner]}: ${simplified}`;
  }

  return simplified;
}

function generateAction(
  severity: Severity,
  cweId: string | null,
  _owaspCategory: string | null
): string {
  const actions: string[] = [];

  // Urgency based on severity
  if (severity === 'critical') {
    actions.push('Immediately investigate and fix this issue.');
    actions.push('Consider temporarily disabling affected functionality until fixed.');
  } else if (severity === 'high') {
    actions.push('Address this issue as soon as possible.');
  } else if (severity === 'medium') {
    actions.push('Plan to fix this issue in your next sprint or release.');
  } else {
    actions.push('Review and fix when convenient.');
  }

  // Specific guidance based on CWE
  if (cweId) {
    const cweActions: Record<string, string> = {
      'CWE-20': 'Add input validation using allowlists for expected formats and reject unexpected input.',
      'CWE-22': 'Use path canonicalization and validate that resolved paths stay within the intended directory.',
      'CWE-77': 'Avoid constructing shell commands from user input. Use APIs or libraries that do not invoke a shell.',
      'CWE-78': 'Replace shell command execution with language-native APIs. If shell commands are necessary, use strict allowlists for arguments.',
      'CWE-79': 'Sanitize and encode all user input before displaying it. Use context-aware output encoding (HTML, JS, URL, CSS).',
      'CWE-89': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.',
      'CWE-94': 'Remove all dynamic code execution. Replace with safe alternatives like configuration-driven logic.',
      'CWE-116': 'Apply context-appropriate output encoding for HTML, JavaScript, URL, and CSS contexts.',
      'CWE-200': 'Remove sensitive details from error responses. Return generic error messages to clients and log details server-side.',
      'CWE-250': 'Apply the principle of least privilege. Run services as non-root users and drop unnecessary capabilities.',
      'CWE-284': 'Add access control middleware that validates user permissions before processing each request.',
      'CWE-285': 'Implement role-based or attribute-based access control and verify authorization on every request.',
      'CWE-287': 'Use a proven authentication library. Implement multi-factor authentication for sensitive operations.',
      'CWE-295': 'Enable and enforce proper certificate validation. Remove any code that disables SSL/TLS verification.',
      'CWE-306': 'Add authentication requirements to all sensitive endpoints and verify credentials on each request.',
      'CWE-326': 'Use current recommended key sizes (RSA 2048+ or Ed25519, AES-256) and update cipher suites.',
      'CWE-327': 'Update to use modern encryption algorithms (AES-256-GCM, SHA-256+, bcrypt/argon2 for passwords).',
      'CWE-330': 'Use cryptographically secure random generators (crypto.randomBytes, crypto.getRandomValues) for security-sensitive values.',
      'CWE-338': 'Replace Math.random() or similar with crypto.randomBytes() or crypto.getRandomValues() for tokens and keys.',
      'CWE-352': 'Implement CSRF tokens for state-changing operations. Use SameSite cookie attributes.',
      'CWE-377': 'Use secure temporary file creation functions that generate unpredictable names and set restrictive permissions.',
      'CWE-400': 'Add rate limiting, request size limits, and timeouts to prevent resource exhaustion.',
      'CWE-434': 'Validate file type by content (magic bytes), not just extension. Restrict file size and store uploads outside the web root.',
      'CWE-502': 'Validate and sanitize data before deserialization. Use safe serialization formats like JSON instead of binary formats.',
      'CWE-521': 'Enforce minimum password length (12+ characters), check against breached password lists, and require complexity.',
      'CWE-532': 'Audit logging statements and redact sensitive fields (passwords, tokens, PII) before writing to logs.',
      'CWE-601': 'Validate redirect URLs against an allowlist of trusted destinations. Reject absolute URLs to external domains.',
      'CWE-611': 'Disable external entity processing and DTD loading in XML parsers. Use JSON instead of XML where possible.',
      'CWE-614': 'Set the Secure flag on all cookies containing sensitive data so they are only sent over HTTPS.',
      'CWE-640': 'Use cryptographically random, time-limited, single-use password reset tokens. Implement rate limiting on reset requests.',
      'CWE-732': 'Set restrictive file permissions (600 or 640 for config files, 750 for executables) and verify ownership.',
      'CWE-776': 'Disable DTD processing in XML parsers or set entity expansion limits.',
      'CWE-798': 'Remove hardcoded secrets and use environment variables or a secret manager.',
      'CWE-829': 'Use Subresource Integrity (SRI) hashes for third-party scripts and pin dependency versions.',
      'CWE-862': 'Add authorization checks to all endpoints. Default to deny access unless explicitly granted.',
      'CWE-863': 'Review and test authorization logic. Ensure checks cannot be bypassed by modifying request parameters.',
      'CWE-918': 'Validate and restrict outbound request URLs. Block requests to internal IP ranges and cloud metadata endpoints.',
      'CWE-1021': 'Set X-Frame-Options to DENY or SAMEORIGIN. Use Content-Security-Policy frame-ancestors directive.',
      'CWE-1333': 'Simplify regular expressions, add input length limits, and test patterns against pathological inputs.',
    };
    if (cweActions[cweId]) {
      actions.push(cweActions[cweId]);
    }
  }

  return actions.join(' ');
}

// Translate multiple findings in batch
export function translateFindings(
  findings: Array<{
    title: string;
    description: string;
    severity: Severity;
    cweId: string | null;
    owaspCategory: string | null;
    scanner: string;
  }>
): TranslatedFinding[] {
  return findings.map(f =>
    translateFinding(f.title, f.description, f.severity, f.cweId, f.owaspCategory, f.scanner)
  );
}
