/**
 * Remediation guidance generator for security findings.
 *
 * Produces specific, actionable fix instructions that an AI agent
 * (or developer) can use to remediate the finding. The guidance
 * includes WHAT to change, WHERE, and WHY — not just "review this".
 */

// ── Bandit rule → specific fix guidance ────────────────────────

const BANDIT_FIXES: Record<string, string> = {
  B101: 'Replace `assert` statements with explicit `if` checks that raise appropriate exceptions. '
    + '`assert` is stripped in optimised bytecode (`python -O`), so it must never be used for input validation or security checks. '
    + 'Example: change `assert user.is_admin` to `if not user.is_admin: raise PermissionError("Admin required")`.',

  B104: 'Bind to a specific interface (e.g. `127.0.0.1`) instead of `0.0.0.0`. '
    + 'Binding to all interfaces exposes the service to the entire network. '
    + 'Use `HOST` env var for configurability: `host = os.getenv("HOST", "127.0.0.1")`.',

  B105: 'Move the hardcoded password to an environment variable or secrets manager. '
    + 'Replace the string literal with `os.environ["DB_PASSWORD"]` or a secrets vault lookup. '
    + 'Never commit passwords to source control, even for development.',

  B106: 'Remove the hardcoded password from the function call. '
    + 'Pass credentials via environment variables or a configuration file loaded at runtime. '
    + 'Example: change `connect(password="secret")` to `connect(password=os.environ["DB_PASSWORD"])`.',

  B107: 'Remove the hardcoded default password from the function signature. '
    + 'Use `None` as default and require callers to provide credentials explicitly, '
    + 'or load from environment: `def connect(password=None): password = password or os.environ["DB_PASSWORD"]`.',

  B108: 'Use `tempfile.mkdtemp()` or `tempfile.NamedTemporaryFile()` instead of a hardcoded `/tmp` path. '
    + 'Hardcoded temp paths create race conditions (symlink attacks) and are predictable. '
    + 'Example: `import tempfile; tmpdir = tempfile.mkdtemp()`.',

  B110: 'Replace the bare `except: pass` with specific exception handling. '
    + 'At minimum, log the exception. Silencing all exceptions hides real errors and security issues. '
    + 'Example: `except ValueError as e: logger.warning("Invalid input: %s", e)`.',

  B324: 'Replace MD5/SHA1 with SHA-256 or SHA-3 for cryptographic purposes. '
    + 'Change `hashlib.md5(data)` to `hashlib.sha256(data)`. '
    + 'If used for checksums (not security), annotate with `# nosec B324` and add a comment explaining why.',

  B404: 'The `subprocess` import itself is not insecure, but ensure all subprocess calls use `shell=False` (the default) '
    + 'and pass arguments as a list, not a string. Never use `shell=True` with user-supplied input. '
    + 'Example: `subprocess.run(["ls", "-la", path])` instead of string-based shell commands.',

  B603: 'Ensure the subprocess call passes arguments as a list (not a string) and does not include unsanitised user input. '
    + 'If the command is static and trusted, this is safe — annotate with `# nosec B603`. '
    + 'If user input is involved, validate/sanitise it with an allowlist before passing to subprocess.',

  B607: 'Use the full absolute path to the executable (e.g. `/usr/bin/git` instead of `git`). '
    + 'Partial paths can be hijacked via PATH manipulation. '
    + 'Alternatively, validate the resolved path with `shutil.which("git")` before invocation.',

  B608: 'Use parameterised queries instead of string formatting for SQL. '
    + 'Change `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")` to '
    + '`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`. '
    + 'For ORMs, use the query builder instead of raw SQL.',
};

// ── Semgrep/Opengrep rule patterns → fix guidance ──────────────

const SEMGREP_FIXES: Record<string, string> = {
  'hardcoded-jwt-secret': 'Move the JWT secret to an environment variable. '
    + 'Replace the string literal with `process.env.JWT_SECRET` (Node.js) or `os.environ["JWT_SECRET"]` (Python). '
    + 'Use a cryptographically strong random value (at least 256 bits). '
    + 'Example: `jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" })`.',

  'tainted-sql-string': 'Use parameterised queries or an ORM instead of string concatenation for SQL. '
    + 'For Django: use `Model.objects.filter()` or `cursor.execute(sql, params)`. '
    + 'For SQLAlchemy: use `text(sql).bindparams()` or the query builder. '
    + 'Never use f-strings or .format() to build SQL with user input.',

  'sqlalchemy-execute-raw-query': 'Replace raw SQL with SQLAlchemy\'s query builder or use `text()` with bound parameters. '
    + 'Change `session.execute(f"SELECT * FROM users WHERE id = {uid}")` to '
    + '`session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": uid})`. '
    + 'This prevents SQL injection and allows SQLAlchemy to manage escaping.',

  'raw-html-format': 'Escape user input before embedding in HTML. '
    + 'Use a template engine with auto-escaping (e.g. Jinja2 with `autoescape=True`, EJS with `<%= %>`). '
    + 'For manual escaping in Node.js: use a library like `he` or `DOMPurify`. '
    + 'Never use string concatenation to build HTML with user-supplied data.',

  'directly-returned-format-string': 'Do not return formatted strings containing user input directly in HTTP responses. '
    + 'Use a template engine or JSON serialisation instead. '
    + 'This prevents XSS and format string vulnerabilities.',

  'possible-nginx-h2c-smuggling': 'Remove or restrict the `Upgrade: h2c` header handling in your nginx config. '
    + 'H2C smuggling allows attackers to bypass security controls by upgrading HTTP/1.1 to HTTP/2 cleartext. '
    + 'If HTTP/2 is needed, use TLS (h2) instead of cleartext (h2c).',
};

// ── CWE → generic but actionable fix guidance ──────────────────

const CWE_FIXES: Record<string, string> = {
  'CWE-78': 'OS Command Injection: sanitise all user input before passing to system commands. '
    + 'Use subprocess with arguments as a list (not shell). Validate with an allowlist.',

  'CWE-79': 'Cross-Site Scripting (XSS): escape all user output in HTML context. '
    + 'Use template engine auto-escaping. Apply Content-Security-Policy headers.',

  'CWE-89': 'SQL Injection: use parameterised queries or ORM methods. '
    + 'Never concatenate user input into SQL strings.',

  'CWE-94': 'Code Injection: avoid eval/exec/Function with user input. '
    + 'Use a sandboxed environment if dynamic code running is required.',

  'CWE-200': 'Information Exposure: remove or redact sensitive data from error messages, logs, and API responses. '
    + 'Return generic error messages to clients; log details server-side only.',

  'CWE-259': 'Hardcoded Password: move credentials to environment variables or a secrets manager. '
    + 'Never commit secrets to source control.',

  'CWE-295': 'Improper Certificate Validation: do not disable TLS certificate verification. '
    + 'Configure proper CA certificates instead of disabling verification.',

  'CWE-327': 'Weak Cryptography: replace MD5/SHA1/DES/RC4 with SHA-256/AES-256/ChaCha20. '
    + 'For passwords, use bcrypt, argon2, or scrypt — never a hash function directly.',

  'CWE-330': 'Insufficient Randomness: use `secrets` module (Python) or `crypto.randomBytes()` (Node.js) '
    + 'instead of `random` or `Math.random()` for security-sensitive values.',

  'CWE-377': 'Insecure Temporary File: use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` '
    + 'instead of hardcoded `/tmp` paths. Set restrictive permissions (0600).',

  'CWE-502': 'Deserialization of Untrusted Data: avoid unsafe deserialization functions '
    + '(e.g. `yaml.load()` without SafeLoader) on unvalidated input. '
    + 'Use schema validation (e.g. Pydantic, Zod) after parsing.',

  'CWE-601': 'Open Redirect: validate redirect URLs against an allowlist of trusted domains. '
    + 'Never redirect to user-supplied URLs without verification.',

  'CWE-798': 'Hardcoded Credentials: extract all credentials to environment variables or a vault. '
    + 'Use `.env` files for local dev (add to .gitignore). Use secrets manager in production.',
};

/**
 * Generate actionable fix description for a finding.
 * Tries scanner-specific guidance first, then CWE-based, then falls back to the original.
 */
export function generateFixDescription(params: {
  scanner: string;
  ruleId: string | null;
  cweId: string | null;
  title: string;
  description: string;
  originalFix: string | null;
}): string {
  const { scanner, ruleId, cweId, description, originalFix } = params;

  // 1. Scanner-specific rule guidance (most specific)
  if (scanner === 'bandit' && ruleId && BANDIT_FIXES[ruleId]) {
    return BANDIT_FIXES[ruleId];
  }

  if ((scanner === 'opengrep' || scanner === 'semgrep') && ruleId) {
    // Try exact match on the last segment of the rule ID
    const ruleKey = ruleId.split('.').pop() || '';
    if (SEMGREP_FIXES[ruleKey]) {
      return SEMGREP_FIXES[ruleKey];
    }
    // Try partial match
    for (const [pattern, fix] of Object.entries(SEMGREP_FIXES)) {
      if (ruleId.includes(pattern)) {
        return fix;
      }
    }
  }

  // 2. CWE-based guidance (moderately specific)
  if (cweId && CWE_FIXES[cweId]) {
    return CWE_FIXES[cweId];
  }

  // 3. If scanner provided a fix and it's not the generic "Review" text, use it
  if (originalFix && !originalFix.startsWith('Review the code pattern')) {
    return originalFix;
  }

  // 4. For SCA findings (grype, trivy), the original fix is usually good
  if (['grype', 'trivy'].includes(scanner) && originalFix) {
    return originalFix;
  }

  // 5. Fallback: return the original or a constructive default
  return originalFix || `Review this finding and apply the appropriate fix based on the description: ${description.slice(0, 200)}`;
}
