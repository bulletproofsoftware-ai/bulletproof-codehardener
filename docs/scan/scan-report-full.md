# Security Scan Report: bulletproof-codehardener

**Scan ID:** `76cff07c-0ba6-4743-a3e4-ca7ffaaf309b`
**Date:** 2026-07-24T22:35:49.895Z
**Score:** 882/1000 (good)
**Branch:** main | **Commit:** `N/A`
**Profile:** standard

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 65 |
| Low | 416 |
| Info | 33 |
| **Total (open)** | **514** |

## Scanners Executed

| Scanner | Status | Findings | Duration | Notes |
|---------|--------|----------|----------|-------|
| trivy | pass | 493 | 5.1s |  |
| gitleaks | pass | 0 | 0.5s |  |
| opengrep | pass | 69 | 17.9s |  |
| checkov | pass | 0 | 4.2s |  |
| grype | pass | 7 | 4.4s |  |
| syft | pass | 8 | 1.5s |  |
| package-validator | pass | 0 | 0.1s |  |
| oxlint | pass | 1 | 0.1s |  |
| ruff | pass | 0 | 0.0s |  |
| actionlint | pass | 0 | 0.0s |  |
| jscpd | pass | 0 | 0.0s |  |
| typos | fail | 0 | 0.1s | _error: Cannot read properties of undefined (reading 'length')_ |
| spectral | pass | 0 | 0.4s |  |
| newman | pass | 0 | 0.4s |  |
| _file_inventory | pass | 0 | 0.0s |  |

## Medium Findings (65)

### [MEDIUM] Do not use a triple slash reference for ./.next/types/routes.d.ts, use \`import\` style instead.

- **File:** `dashboard/next-env.d.ts`
- **Scanner:** oxlint
- **Rule:** `OXLINT-UNKNOWN`

**What's wrong:** Do not use a triple slash reference for ./.next/types/routes.d.ts, use `import` style instead.

**How to fix:** Review this finding and apply the appropriate fix based on the description: Do not use a triple slash reference for ./.next/types/routes.d.ts, use `import` style instead.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Code or data can be modified without detection.

- **File:** `/dashboard/package-lock.json`
- **Scanner:** syft
- **Rule:** `SBOM-LICENSE-MEDIUM`
- **OWASP:** A08:2021-Software and Data Integrity Failures

**What's wrong:** Package dompurify@3.4.8 uses (MPL-2.0 OR Apache-2.0) which has copyleft provisions. Ensure compliance with license terms.

**Code:**
```json
Package: dompurify
Version: 3.4.8
License: (MPL-2.0 OR Apache-2.0)
```

**How to fix:** Review (MPL-2.0 OR Apache-2.0) license requirements to ensure your use case is compliant.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Using outdated libraries with known security issues.

- **File:** `/dashboard/package-lock.json`
- **Scanner:** grype
- **Rule:** `CVE-2026-65898`
- **OWASP:** A06:2021-Vulnerable and Outdated Components

**What's wrong:** DOMPurify: Permanent `ALLOWED_ATTR` pollution via `setConfig()` bypassing the hook clone-guard (incomplete fix of the 3.4.7 hook-pollution patch)

**Code:**
```json
Package: dompurify
Version: 3.4.8
Type: npm
Language: javascript
```

**How to fix:** Update dompurify to version 3.4.11

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Using outdated libraries with known security issues.

- **File:** `/backend/package-lock.json`
- **Scanner:** grype
- **Rule:** `GHSA-frvp-7c67-39w9`
- **OWASP:** A06:2021-Vulnerable and Outdated Components

**What's wrong:** Node.js Adapter for Hono: Path traversal in `serve-static` on Windows via encoded backslash (`%5C`)

**Code:**
```json
Package: @hono/node-server
Version: 1.19.14
Type: npm
Language: javascript
```

**How to fix:** Update @hono/node-server to version 2.0.5

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Using outdated libraries with known security issues.

- **File:** `/backend/package-lock.json`
- **Scanner:** grype
- **Rule:** `CVE-2026-5078`
- **OWASP:** A06:2021-Vulnerable and Outdated Components

**What's wrong:** morgan vulnerable to Log Forging via unneutralized control characters in :remote-user

**Code:**
```json
Package: morgan
Version: 1.10.1
Type: npm
Language: javascript
```

**How to fix:** Update morgan to version 1.11.0

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:130`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:108`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

- **File:** `nginx/scan.codehardener.com.conf:107`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.possible-h2c-smuggling.possible-nginx-h2c-smuggling`
- **CWE:** [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
- **OWASP:** A04:2021 - Insecure Design

**What's wrong:** Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

**Code:**
```
requires login
```

**How to fix:** Remove or restrict the `Upgrade: h2c` header handling in your nginx config. H2C smuggling allows attackers to bypass security controls by upgrading HTTP/1.1 to HTTP/2 cleartext. If HTTP/2 is needed, use TLS (h2) instead of cleartext (h2c).

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:86`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

- **File:** `nginx/scan.codehardener.com.conf:85`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.possible-h2c-smuggling.possible-nginx-h2c-smuggling`
- **CWE:** [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
- **OWASP:** A04:2021 - Insecure Design

**What's wrong:** Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

**Code:**
```
requires login
```

**How to fix:** Remove or restrict the `Upgrade: h2c` header handling in your nginx config. H2C smuggling allows attackers to bypass security controls by upgrading HTTP/1.1 to HTTP/2 cleartext. If HTTP/2 is needed, use TLS (h2) instead of cleartext (h2c).

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:73`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:56`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

- **File:** `nginx/scan.codehardener.com.conf:38`
- **Scanner:** opengrep
- **Rule:** `generic.nginx.security.request-host-used.request-host-used`
- **CWE:** [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Code:**
```
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. \`uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608\`.

- **File:** `integrations/github-action/action.yml:134`
- **Scanner:** opengrep
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
- **CWE:** [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- **OWASP:** A08:2021 - Software and Data Integrity Failures

**What's wrong:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**Code:**
```yaml
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-gi

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/utils/safePath.ts:9`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/utils/safePath.ts:8`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`content\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/test-generator/brd-parser/markdown-parser.ts:362`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`content\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/test-generator/brd-parser/markdown-parser.ts:355`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`attr\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/sso/saml.service.ts:417`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `attr` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `attr` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`tag\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/sso/saml.service.ts:410`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `tag` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `tag` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this 

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`rules\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/threatmodel.ts:374`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `rules` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `rules` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For thi

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/threatmodel.ts:343`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/threatmodel.ts:338`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:165`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:158`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:95`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:94`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:93`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:80`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/reachability.ts:75`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`tag\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/pitest.ts:133`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `tag` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `tag` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this 

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`name\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/llm-vuln-scan.ts:309`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `name` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `name` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`name\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/llm-patch.ts:164`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `name` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `name` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`flags\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/llm-agent.ts:85`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `flags` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `flags` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For thi

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:138`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:135`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:99`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:84`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:63`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/scanners/detect-context.ts:48`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`content\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/deepeval.ts:433`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`content\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/deepeval.ts:222`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`content\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/deepeval.ts:206`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `content` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`stability.replace\` method will only replace the first occurrence when used with a string argument ('%'). If this method is used for escaping of dangerous data then there is a possibility for a bypass. Try to use sanitization library instead or use a Regex with a global flag.

- **File:** `backend/src/services/scanners/aflpp.ts:41`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.incomplete-sanitization.incomplete-sanitization`
- **CWE:** [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
- **OWASP:** A03:2021 - Injection

**What's wrong:** `stability.replace` method will only replace the first occurrence when used with a string argument ('%'). If this method is used for escaping of dangerous data then there is a possibility for a bypass. Try to use sanitization library instead or use a Regex with a global flag.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: `stability.replace` method will only replace the first occurrence when used with a string argument ('%'). If this method is used for escaping of dangerous data then there is a possibility for a bypass

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] RegExp() called with a \`key\` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

- **File:** `backend/src/services/scanners/aflpp.ts:31`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **OWASP:** A05:2021 - Security Misconfiguration

**What's wrong:** RegExp() called with a `key` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: RegExp() called with a `key` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this 

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected possible user input going into a \`path.join\` or \`path.resolve\` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

- **File:** `backend/src/services/prompt-parser/file-parser.ts:412`
- **Scanner:** opengrep
- **Rule:** `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal`
- **CWE:** [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- **OWASP:** A05:2017 - Broken Access Control

**What's wrong:** Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

- **File:** `backend/src/services/auth.service.test.ts:184`
- **Scanner:** opengrep
- **Rule:** `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

**Code:**
```typescript
requires login
```

**How to fix:** Move the JWT secret to an environment variable. Replace the string literal with `process.env.JWT_SECRET` (Node.js) or `os.environ["JWT_SECRET"]` (Python). Use a cryptographically strong random value (at least 256 bits). Example: `jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" })`.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

- **File:** `backend/src/services/auth.service.test.ts:174`
- **Scanner:** opengrep
- **Rule:** `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**What's wrong:** A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

**Code:**
```typescript
requires login
```

**How to fix:** Move the JWT secret to an environment variable. Replace the string literal with `process.env.JWT_SECRET` (Node.js) or `os.environ["JWT_SECRET"]` (Python). Use a cryptographically strong random value (at least 256 bits). Example: `jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" })`.

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

- **File:** `backend/src/routes/reports.routes.ts:294`
- **Scanner:** opengrep
- **Rule:** `javascript.express.security.audit.xss.direct-response-write.direct-response-write`
- **CWE:** [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- **OWASP:** A07:2017 - Cross-Site Scripting (XSS)

**What's wrong:** Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'res

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Request parameter or query string used without validation. Validate and sanitize all user input before use.


- **File:** `backend/src/controllers/findings.controller.ts:160`
- **Scanner:** opengrep
- **Rule:** `configs.express-unvalidated-params`
- **CWE:** [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

**What's wrong:** Request parameter or query string used without validation. Validate and sanitize all user input before use.


**Code:**
```typescript
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: Request parameter or query string used without validation. Validate and sanitize all user input before use.


**Action:** Plan to fix this issue in your next sprint or release.

---

> ... and 15 more medium findings

## Low Findings (416)

- **SBOM-LICENSE-UNKNOWN**: Unknown License: streamsearch@1.1.0 (`/backend/package-lock.json`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: github.com/codehardener/codehardener-go@UNKNOWN (`/sdks/go/go.mod`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: codehardener-marketing@1.0.0 (`/marketing/package-lock.json`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: codehardener-dashboard@0.1.0 (`/dashboard/package-lock.json`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: busboy@1.6.0 (`/backend/package-lock.json`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/setup-node@v4 (`/.github/workflows/ci.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/checkout@v4 (`/.github/workflows/ci.yml`)
- **GHSA-c2j3-45gr-mqc4**: GHSA-c2j3-45gr-mqc4: Vulnerability in dompurify@3.4.8 (`/dashboard/package-lock.json`)
- **CVE-2026-65899**: CVE-2026-65899: Vulnerability in dompurify@3.4.8 (`/dashboard/package-lock.json`)
- **CVE-2026-12590**: CVE-2026-12590: Vulnerability in body-parser@2.2.2 (`/backend/package-lock.json`)
- **CVE-2026-12590**: CVE-2026-12590: Vulnerability in body-parser@1.20.5 (`/backend/package-lock.json`)
- **javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring**: unsafe-formatstring (`dashboard/src/app/projects/[id]/page.tsx:735`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in  (`LICENSE`)
- **LICENSE-0BSD**: License Compliance: 0BSD in tslib (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in styled-jsx (`marketing/package-lock.json`)
- **LICENSE-BSD-3-Clause**: License Compliance: BSD-3-Clause in source-map-js (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in sharp (`marketing/package-lock.json`)
- **LICENSE-ISC**: License Compliance: ISC in semver (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in scheduler (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in playwright-core (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in playwright (`marketing/package-lock.json`)
- **LICENSE-ISC**: License Compliance: ISC in picocolors (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in nanoid (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in loose-envify (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in js-tokens (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in fsevents (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in detect-libc (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in client-only (`marketing/package-lock.json`)
- **LICENSE-CC-BY-4.0**: License Compliance: CC-BY-4.0 in caniuse-lite (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @swc/helpers (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-win32-x64-msvc (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-win32-arm64-msvc (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-linux-x64-musl (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-linux-x64-gnu (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-linux-arm64-musl (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-linux-arm64-gnu (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-darwin-x64 (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/swc-darwin-arm64 (`marketing/package-lock.json`)
- **LICENSE-MIT**: License Compliance: MIT in @next/env (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-webcontainers-wasm32 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linuxmusl-x64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linuxmusl-arm64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-x64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-s390x (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-riscv64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-ppc64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-arm64 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-linux-arm (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-freebsd-wasm32 (`marketing/package-lock.json`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in @img/sharp-darwin-x64 (`marketing/package-lock.json`)

> ... and 366 more low findings

## Recommendations

1. Update 414 vulnerable dependency/dependencies -- run `npm audit fix` or equivalent

---
*Generated by Code Hardener v0.1.0 | 2026-07-24T22:37:14.607Z*