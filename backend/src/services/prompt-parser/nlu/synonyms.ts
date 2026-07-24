/**
 * NLU Synonyms Dictionary
 * Provides normalization of security terminology for prompt parsing
 * Implements: NLU-006 (Support synonyms)
 */

// Canonical security term to synonyms mapping
export const SECURITY_SYNONYMS: Record<string, string[]> = {
  // Vulnerability types
  'sql injection': ['sqli', 'database injection', 'sql attack', 'db injection', 'sql exploit'],
  'xss': ['cross-site scripting', 'script injection', 'cross site scripting', 'cross-site-scripting'],
  'csrf': ['cross-site request forgery', 'xsrf', 'sea-surf', 'session riding'],
  'ssrf': ['server-side request forgery', 'server request forgery', 'server side request forgery'],
  'rce': ['remote code execution', 'command injection', 'code execution', 'remote execution'],
  'lfi': ['local file inclusion', 'file inclusion', 'path traversal', 'directory traversal'],
  'rfi': ['remote file inclusion'],
  'xxe': ['xml external entity', 'xml injection', 'xml entity injection'],
  'idor': ['insecure direct object reference', 'direct object reference', 'broken object level authorization'],
  'deserialization': ['insecure deserialization', 'unsafe deserialization', 'object injection'],

  // Actions
  'scan': ['check', 'analyze', 'audit', 'test', 'review', 'inspect', 'examine', 'assess', 'evaluate'],
  'find': ['detect', 'discover', 'identify', 'locate', 'search', 'look for', 'hunt'],
  'fix': ['remediate', 'patch', 'resolve', 'address', 'correct', 'repair', 'mitigate'],
  'verify': ['validate', 'confirm', 'ensure', 'check', 'test'],

  // Targets
  'secrets': ['credentials', 'passwords', 'api keys', 'tokens', 'keys', 'private keys', 'access tokens'],
  'dependencies': ['packages', 'libraries', 'modules', 'deps', 'node_modules', 'vendor'],
  'vulnerabilities': ['vulns', 'security issues', 'weaknesses', 'flaws', 'bugs', 'security bugs'],
  'containers': ['docker', 'docker images', 'container images', 'docker containers'],
  'infrastructure': ['infra', 'iac', 'terraform', 'cloudformation', 'kubernetes', 'k8s', 'helm'],
  'api': ['apis', 'endpoints', 'rest api', 'rest endpoints', 'api endpoints', 'web api'],
  'code': ['source code', 'codebase', 'source', 'files', 'source files'],

  // Tools (normalize to canonical names)
  'semgrep': ['opengrep', 'open-grep'],
  'owasp zap': ['zap', 'zaproxy', 'zed attack proxy'],
  'trivy': ['trivy-scanner', 'aqua trivy'],
  'gitleaks': ['git-leaks', 'gitleak'],
  // detect-secrets removed: redundant with Gitleaks
  'checkov': ['bridgecrew checkov'],

  // Languages
  'javascript': ['js', 'ecmascript', 'es6', 'node', 'nodejs'],
  'typescript': ['ts'],
  'python': ['py', 'python3', 'python2'],
  'golang': ['go', 'go-lang'],
  'java': ['jvm', 'kotlin', 'scala'],
  'ruby': ['rb', 'rails'],
  'php': ['laravel', 'symfony'],
  'rust': ['rs'],
  'csharp': ['c#', 'dotnet', '.net'],

  // Severity
  'critical': ['crit', 'p0', 'severity-critical', 'blocker'],
  'high': ['p1', 'severity-high', 'major'],
  'medium': ['med', 'p2', 'severity-medium', 'moderate'],
  'low': ['p3', 'severity-low', 'minor'],

  // Categories
  'static analysis': ['sast', 'static scan', 'code analysis', 'static code analysis'],
  'dynamic analysis': ['dast', 'dynamic scan', 'runtime scan', 'active scan'],
  'composition analysis': ['sca', 'dependency scan', 'software composition', 'dependency audit'],
  'secret detection': ['secret scan', 'credential scan', 'key detection', 'password detection'],
  'compliance': ['policy', 'compliance check', 'policy check', 'regulatory'],
  'performance': ['load test', 'stress test', 'performance test', 'benchmark'],
  'accessibility': ['a11y', 'wcag', 'accessibility check', 'ada compliance'],
};

// Build reverse lookup map: synonym -> canonical term
const REVERSE_LOOKUP: Map<string, string> = new Map();

for (const [canonical, synonyms] of Object.entries(SECURITY_SYNONYMS)) {
  // Add canonical term itself
  REVERSE_LOOKUP.set(canonical.toLowerCase(), canonical);
  // Add all synonyms
  for (const synonym of synonyms) {
    REVERSE_LOOKUP.set(synonym.toLowerCase(), canonical);
  }
}

/**
 * Normalize a single term to its canonical form
 * @param term The term to normalize
 * @returns The canonical form or the original term if no match
 */
export function normalizeTerm(term: string): string {
  const lowerTerm = term.toLowerCase().trim();
  return REVERSE_LOOKUP.get(lowerTerm) || term;
}

/**
 * Normalize all terms in a text string
 * Replaces recognized synonyms with their canonical forms
 * @param text The input text
 * @returns Text with synonyms replaced by canonical terms
 */
export function normalizeText(text: string): string {
  let normalized = text.toLowerCase();

  // Sort by length (longest first) to handle multi-word phrases first
  const allTerms = Array.from(REVERSE_LOOKUP.entries())
    .sort((a, b) => b[0].length - a[0].length);

  for (const [synonym, canonical] of allTerms) {
    // Use word boundaries to avoid partial matches
    const regex = new RegExp(`\\b${escapeRegex(synonym)}\\b`, 'gi');
    normalized = normalized.replace(regex, canonical);
  }

  return normalized;
}

/**
 * Find all known terms in a text
 * @param text The input text
 * @returns Array of found terms with their canonical forms and positions
 */
export function findTerms(text: string): Array<{
  original: string;
  canonical: string;
  index: number;
}> {
  const found: Array<{ original: string; canonical: string; index: number }> = [];
  const lowerText = text.toLowerCase();

  // Sort by length (longest first) to handle multi-word phrases first
  const allTerms = Array.from(REVERSE_LOOKUP.entries())
    .sort((a, b) => b[0].length - a[0].length);

  for (const [synonym, canonical] of allTerms) {
    const regex = new RegExp(`\\b${escapeRegex(synonym)}\\b`, 'gi');
    let match;
    while ((match = regex.exec(lowerText)) !== null) {
      // Check if this position is already covered by a longer match
      const isDuplicate = found.some(
        f => match!.index >= f.index && match!.index < f.index + f.original.length
      );
      if (!isDuplicate) {
        found.push({
          original: text.slice(match.index, match.index + match[0].length),
          canonical,
          index: match.index,
        });
      }
    }
  }

  // Sort by position
  return found.sort((a, b) => a.index - b.index);
}

/**
 * Check if a term matches any known security terminology
 * @param term The term to check
 * @returns true if the term is recognized
 */
export function isKnownTerm(term: string): boolean {
  return REVERSE_LOOKUP.has(term.toLowerCase().trim());
}

/**
 * Get all synonyms for a canonical term
 * @param canonical The canonical term
 * @returns Array of synonyms or empty array
 */
export function getSynonyms(canonical: string): string[] {
  return SECURITY_SYNONYMS[canonical.toLowerCase()] || [];
}

/**
 * Get the canonical form for a term
 * @param term The term to look up
 * @returns The canonical form or null if not found
 */
export function getCanonical(term: string): string | null {
  const canonical = REVERSE_LOOKUP.get(term.toLowerCase().trim());
  return canonical || null;
}

// Helper function to escape regex special characters
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Export for testing
export { REVERSE_LOOKUP };
