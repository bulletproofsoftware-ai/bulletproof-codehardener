/**
 * NLU Intent Patterns and Types
 * Defines security intent categories and pattern matching rules
 * Implements: NLU-001 (Classify security intent)
 */

// All supported security intents
export type SecurityIntent =
  | 'vulnerability_scan'      // Generic vuln scanning
  | 'sast'                    // Static analysis
  | 'dast'                    // Dynamic analysis
  | 'sca'                     // Software composition analysis
  | 'secrets_detection'       // Secret/credential scanning
  | 'iac_security'            // Infrastructure as Code
  | 'container_security'      // Docker/K8s scanning
  | 'api_security'            // API testing
  | 'dependency_audit'        // Package vulnerabilities
  | 'compliance_check'        // Policy/compliance
  | 'performance_test'        // Load testing
  | 'accessibility_test'      // Pa11y
  | 'visual_regression'       // BackstopJS
  | 'supply_chain'            // SBOM, attestation
  | 'code_quality'            // General code quality
  | 'unknown';

// Intent pattern definition
export interface IntentPattern {
  intent: SecurityIntent;
  patterns: RegExp[];
  keywords: string[];
  weight: number;
  description: string;
}

// Intent detection patterns - ordered by specificity
export const INTENT_PATTERNS: IntentPattern[] = [
  // Secrets Detection - highest priority for explicit mentions
  {
    intent: 'secrets_detection',
    patterns: [
      /\bsecret[s]?\s*(scan|detect|find|check|audit)/i,
      /\bcredential[s]?\s*(scan|detect|leak|find)/i,
      /\bapi\s*key[s]?\s*(scan|detect|find|check)/i,
      /\bhardcoded\s*(secret|password|key|credential)/i,
      /\b(find|detect|scan|check)\s*(for\s*)?(hardcoded\s*)?(secret|credential|password|token|key)/i,
      /\bpassword[s]?\s*(in\s*)?(code|source|file)/i,
      /\b(gitleaks)\b/i,
    ],
    keywords: ['secrets', 'credentials', 'api keys', 'passwords', 'tokens', 'hardcoded', 'leak', 'exposed'],
    weight: 1.0,
    description: 'Detect secrets and credentials in code',
  },

  // SQL Injection / XSS / SAST patterns
  {
    intent: 'sast',
    patterns: [
      /\bsql\s*injection/i,
      /\bsqli\b/i,
      /\bxss\b/i,
      /\bcross.?site\s*script/i,
      /\bcode\s*(quality|review|analysis|scan)/i,
      /\bstatic\s*(analysis|scan|code)/i,
      /\bsast\b/i,
      /\b(bandit|opengrep|semgrep|eslint|pmd|gosec)\b/i,
      /\binjection\s*vulnerabilit/i,
      /\bcsrf\b/i,
      /\bssrf\b/i,
      /\b(xxe|xml\s*external\s*entity)/i,
      /\bcommand\s*injection/i,
      /\bpath\s*traversal/i,
      /\bcode\s*smell/i,
      /\bsecurity\s*lint/i,
    ],
    keywords: ['sqli', 'sql injection', 'xss', 'cross-site scripting', 'static analysis', 'code scan',
               'injection', 'csrf', 'ssrf', 'xxe', 'code quality', 'lint'],
    weight: 1.0,
    description: 'Static application security testing',
  },

  // Dynamic Analysis / DAST
  {
    intent: 'dast',
    patterns: [
      /\bdynamic\s*(analysis|scan|test)/i,
      /\bdast\b/i,
      /\b(owasp\s*)?zap\b/i,
      /\bnuclei\b/i,
      /\b(sqlmap|dalfox|ffuf)\b/i,
      /\bactive\s*scan/i,
      /\bruntime\s*(security|scan|test)/i,
      /\bweb\s*(app|application)\s*scan/i,
      /\bpenetration\s*test/i,
      /\bpen\s*test/i,
    ],
    keywords: ['dast', 'dynamic analysis', 'active scan', 'penetration test', 'runtime scan', 'zap', 'nuclei'],
    weight: 1.0,
    description: 'Dynamic application security testing',
  },

  // Container Security
  {
    intent: 'container_security',
    patterns: [
      /\bcontainer\s*(security|scan|vulnerabilit)/i,
      /\bdocker\s*(image\s*)?(security|scan|vulnerabilit)/i,
      /\bimage\s*(security|scan|vulnerabilit)/i,
      /\bkubernetes\s*security/i,
      /\bk8s\s*security/i,
      /\bscan\s*(docker|container)\s*image/i,
    ],
    keywords: ['container', 'docker', 'kubernetes', 'k8s', 'image scan', 'container security'],
    weight: 0.95,
    description: 'Container and image security scanning',
  },

  // Software Composition Analysis / Dependency Audit
  {
    intent: 'sca',
    patterns: [
      /\b(dependency|dependencies)\s*(scan|audit|check|vulnerabilit)/i,
      /\bsca\b/i,
      /\bsoftware\s*composition/i,
      /\bpackage\s*(vulnerabilit|scan|audit)/i,
      /\b(npm|yarn|pip|maven|gradle)\s*(audit|scan)/i,
      /\boutdated\s*(package|dependenc|librar)/i,
      /\bvulnerable\s*(package|dependenc|librar)/i,
      /\b(trivy|grype|syft)\b/i,
      /\bsbom\b/i,
      /\bsoftware\s*bill\s*of\s*materials/i,
    ],
    keywords: ['sca', 'dependencies', 'packages', 'npm audit', 'vulnerabilities', 'outdated', 'sbom'],
    weight: 0.95,
    description: 'Software composition and dependency analysis',
  },

  // Dependency Audit (more specific variant)
  {
    intent: 'dependency_audit',
    patterns: [
      /\baudit\s*(dependenc|package|librar)/i,
      /\b(check|scan)\s*for\s*outdated/i,
      /\bsecurity\s*patch/i,
      /\bupdate\s*check/i,
    ],
    keywords: ['audit', 'outdated', 'update', 'patch', 'version'],
    weight: 0.85,
    description: 'Audit dependencies for updates and patches',
  },

  // Infrastructure as Code Security
  {
    intent: 'iac_security',
    patterns: [
      /\biac\s*(security|scan|check)/i,
      /\binfrastructure\s*(as\s*code\s*)?(security|scan)/i,
      /\bterraform\s*(security|scan|check)/i,
      /\bcloudformation\s*(security|scan)/i,
      /\bhelm\s*(security|scan|check)/i,
      /\bansible\s*(security|scan)/i,
      /\b(checkov|conftest)\b/i,
      /\bkubernetes\s*(manifest|yaml)\s*(scan|check)/i,
      /\bcloud\s*(misconfiguration|security)/i,
    ],
    keywords: ['iac', 'infrastructure', 'terraform', 'cloudformation', 'helm', 'kubernetes', 'checkov'],
    weight: 0.95,
    description: 'Infrastructure as Code security scanning',
  },

  // API Security
  {
    intent: 'api_security',
    patterns: [
      /\bapi\s*(security|test|scan|fuzz)/i,
      /\brest\s*(api\s*)?(security|test)/i,
      /\bopenapi\s*(security|test|scan)/i,
      /\bswagger\s*(security|test)/i,
      /\bendpoint[s]?\s*(security|test|scan)/i,
      /\b(newman|restler|pact)\b/i,
      /\bcontract\s*test/i,
      /\bapi\s*fuzz/i,
    ],
    keywords: ['api', 'rest', 'openapi', 'swagger', 'endpoint', 'contract', 'fuzz'],
    weight: 0.9,
    description: 'API security testing',
  },

  // Compliance Check
  {
    intent: 'compliance_check',
    patterns: [
      /\bcompliance\s*(check|scan|audit)/i,
      /\bpolicy\s*(check|scan|enforce|violation)/i,
      /\b(soc\s*2|iso\s*27001|pci|hipaa|gdpr)\b/i,
      /\bopa\b/i,
      /\bopen\s*policy\s*agent/i,
      /\bregulatory\s*(compliance|check)/i,
      /\bsecurity\s*policy/i,
      /\brego\b/i,
    ],
    keywords: ['compliance', 'policy', 'soc2', 'iso27001', 'pci', 'hipaa', 'gdpr', 'opa', 'rego'],
    weight: 0.9,
    description: 'Compliance and policy checking',
  },

  // Performance Testing
  {
    intent: 'performance_test',
    patterns: [
      /\b(load|stress|performance)\s*test/i,
      /\bbenchmark/i,
      /\b(locust|artillery|k6)\b/i,
      /\bscalability\s*test/i,
      /\brendurance\s*test/i,
      /\bspike\s*test/i,
    ],
    keywords: ['load test', 'stress test', 'performance', 'benchmark', 'scalability', 'locust', 'k6'],
    weight: 0.85,
    description: 'Performance and load testing',
  },

  // Accessibility Testing
  {
    intent: 'accessibility_test',
    patterns: [
      /\baccessibility\s*(test|scan|check|audit)/i,
      /\ba11y\b/i,
      /\bwcag\b/i,
      /\bada\s*compliance/i,
      /\bscreen\s*reader/i,
      /\bpa11y\b/i,
    ],
    keywords: ['accessibility', 'a11y', 'wcag', 'ada', 'screen reader', 'pa11y'],
    weight: 0.85,
    description: 'Accessibility testing',
  },

  // Visual Regression
  {
    intent: 'visual_regression',
    patterns: [
      /\bvisual\s*(regression|test|diff)/i,
      /\bscreenshot\s*(test|compare|diff)/i,
      /\bbackstop/i,
      /\bui\s*(regression|test)/i,
      /\bcss\s*regression/i,
    ],
    keywords: ['visual regression', 'screenshot', 'backstop', 'ui test', 'css regression'],
    weight: 0.85,
    description: 'Visual regression testing',
  },

  // Supply Chain Security
  {
    intent: 'supply_chain',
    patterns: [
      /\bsupply\s*chain\s*(security|scan|attestation)/i,
      /\bslsa\b/i,
      /\b(cosign|sigstore|socket)\b/i,
      /\battestation/i,
      /\bprovenance/i,
      /\bsign(ed|ing)?\s*(artifact|container|image)/i,
      /\bverify\s*(signature|attestation)/i,
    ],
    keywords: ['supply chain', 'slsa', 'attestation', 'provenance', 'cosign', 'sigstore', 'signing'],
    weight: 0.9,
    description: 'Supply chain security and attestation',
  },

  // Code Quality (lower priority, catch-all for quality mentions)
  {
    intent: 'code_quality',
    patterns: [
      /\bcode\s*quality/i,
      /\blint(er|ing)?\b/i,
      /\bcode\s*smell/i,
      /\bbest\s*practice/i,
      /\bclean\s*code/i,
    ],
    keywords: ['code quality', 'lint', 'best practice', 'clean code'],
    weight: 0.7,
    description: 'General code quality checks',
  },

  // Generic Vulnerability Scan (catch-all)
  {
    intent: 'vulnerability_scan',
    patterns: [
      /\b(vulnerabilit|vuln|security)\s*(scan|check|test|audit)/i,
      /\bsecurity\s*(assessment|review)/i,
      /\b(scan|check|test|find)\s*(for\s*)?(vulnerabilit|security\s*issue)/i,
      /\bpentest/i,
    ],
    keywords: ['vulnerability', 'security scan', 'security check', 'audit', 'assessment'],
    weight: 0.8,
    description: 'General vulnerability scanning',
  },
];

// Negation patterns for NLU-007
export const NEGATION_PATTERNS: RegExp[] = [
  /\b(don'?t|do\s*not|doesn'?t|does\s*not)\s+(check|scan|test|analyze|find|detect|look)/i,
  /\bskip\s+(the\s+)?(check|scan|test|analysis)/i,
  /\b(without|excluding|except)\s+(the\s+)?/i,
  /\b(ignore|skip)\s+/i,
  /\bnot\s+(necessary|needed|required)/i,
  /\bexclude\s+/i,
  /\b(disable|turn\s*off)\s+/i,
];

// Compound prompt connectors for NLU-009
export const COMPOUND_CONNECTORS: RegExp[] = [
  /\s+and\s+(?:also\s+)?/i,
  /\s+as\s+well\s+as\s+/i,
  /\s*,\s*(?:and\s+)?/,
  /\s+then\s+/i,
  /\s+after\s+that\s+/i,
  /\s+followed\s+by\s+/i,
  /\s*;\s*/,
];

// Tool reference patterns for NLU-008
export const TOOL_REFERENCE_PATTERNS: RegExp[] = [
  /\b(use|run|with|using)\s+(\w+)/i,
  /\b(\w+)\s+(scanner|tool)/i,
  /\b(trivy|grype|gitleaks|bandit|gosec|eslint|pmd|opengrep|semgrep|zap|nuclei|sqlmap|dalfox|ffuf|checkov|conftest|k6|locust|artillery|newman|playwright|backstop|pa11y|cosign|syft|pact|restler|opa|defectdojo|lychee|axe-core|c8|fast-check|hypothesis|socket|giskard)\b/i,
];

// Severity patterns for NLU-004
export const SEVERITY_PATTERNS: Array<{
  pattern: RegExp;
  value: string;
  operator: 'eq' | 'gte' | 'lte';
}> = [
  { pattern: /\bcritical\s*only\b/i, value: 'critical', operator: 'eq' },
  { pattern: /\bhigh\s*only\b/i, value: 'high', operator: 'eq' },
  { pattern: /\bmedium\s*only\b/i, value: 'medium', operator: 'eq' },
  { pattern: /\blow\s*only\b/i, value: 'low', operator: 'eq' },
  { pattern: /\b(high|critical)\s*(and\s*)?(above|or\s*higher|or\s*worse|\+)/i, value: 'high', operator: 'gte' },
  { pattern: /\bmedium\s*(and\s*)?(above|or\s*higher|\+)/i, value: 'medium', operator: 'gte' },
  { pattern: /\bcritical\s*(and\s*)?(above|or\s*higher|\+)/i, value: 'critical', operator: 'gte' },
  { pattern: /\bseverity\s*>=?\s*(critical|high|medium|low)/i, value: '$1', operator: 'gte' },
  { pattern: /\bseverity\s*<=?\s*(critical|high|medium|low)/i, value: '$1', operator: 'lte' },
  { pattern: /\b(critical|high|medium|low)\s*severity/i, value: '$1', operator: 'eq' },
];

// Language detection patterns for NLU-002
export const LANGUAGE_PATTERNS: Array<{
  pattern: RegExp;
  language: string;
}> = [
  { pattern: /\bpython\s*(code|file|project)?/i, language: 'python' },
  { pattern: /\b\.py\s*file/i, language: 'python' },
  { pattern: /\bjavascript\s*(code|file|project)?/i, language: 'javascript' },
  { pattern: /\bjs\s*(code|file|project)/i, language: 'javascript' },
  { pattern: /\b\.js\s*file/i, language: 'javascript' },
  { pattern: /\btypescript\s*(code|file|project)?/i, language: 'typescript' },
  { pattern: /\bts\s*(code|file|project)/i, language: 'typescript' },
  { pattern: /\b\.ts\s*file/i, language: 'typescript' },
  { pattern: /\bgolang\s*(code|file|project)?/i, language: 'go' },
  { pattern: /\bgo\s*(code|file|project)/i, language: 'go' },
  { pattern: /\b\.go\s*file/i, language: 'go' },
  { pattern: /\bjava\s*(code|file|project)?/i, language: 'java' },
  { pattern: /\b\.java\s*file/i, language: 'java' },
  { pattern: /\bruby\s*(code|file|project)?/i, language: 'ruby' },
  { pattern: /\b\.rb\s*file/i, language: 'ruby' },
  { pattern: /\bphp\s*(code|file|project)?/i, language: 'php' },
  { pattern: /\b\.php\s*file/i, language: 'php' },
  { pattern: /\brust\s*(code|file|project)?/i, language: 'rust' },
  { pattern: /\b\.rs\s*file/i, language: 'rust' },
  { pattern: /\bc#\s*(code|file|project)?/i, language: 'csharp' },
  { pattern: /\bcsharp\s*(code|file|project)?/i, language: 'csharp' },
  { pattern: /\b\.cs\s*file/i, language: 'csharp' },
];

// File path patterns for NLU-003
export const FILE_PATH_PATTERNS: RegExp[] = [
  // Unix-style paths
  /(?:^|\s)(\/[\w\-./]+)/g,
  // Windows-style paths
  /(?:^|\s)([A-Za-z]:\\[\w\-\\./]+)/g,
  // Relative paths
  /(?:^|\s)(\.\.?\/[\w\-./]+)/g,
  // Glob patterns
  /(?:^|\s)(\*\*\/[\w\-.*]+)/g,
  /(?:^|\s)([\w-]+\/\*\*\/[\w-.*]+)/g,
  // Directory references
  /\b(src|lib|test|tests|app|packages?|modules?|components?)\/[\w\-./]*/gi,
  // File with extension
  /\b[\w-]+\.(ts|js|py|go|java|rb|php|rs|cs|tsx|jsx|vue|yaml|yml|json|xml|tf|hcl)\b/gi,
];

// Known tool names (for explicit tool reference detection)
export const KNOWN_TOOLS: string[] = [
  'trivy', 'grype', 'syft',
  'gitleaks',
  'bandit', 'gosec', 'eslint', 'pmd', 'opengrep', 'semgrep',
  'zap', 'nuclei', 'sqlmap', 'dalfox', 'ffuf',
  'checkov', 'conftest', 'opa',
  'k6', 'locust', 'artillery',
  'newman', 'pact', 'restler',
  'playwright', 'backstop', 'backstopjs', 'pa11y',
  'cosign', 'socket',
  'defectdojo',
  'toxiproxy',
  'lychee', 'axe-core', 'c8', 'fast-check', 'hypothesis',
  'giskard',
];

// Intent priority order (for resolving conflicts)
export const INTENT_PRIORITY: SecurityIntent[] = [
  'secrets_detection',      // Most specific
  'sast',
  'dast',
  'container_security',
  'iac_security',
  'sca',
  'api_security',
  'compliance_check',
  'supply_chain',
  'dependency_audit',
  'performance_test',
  'accessibility_test',
  'visual_regression',
  'code_quality',
  'vulnerability_scan',     // Most general
  'unknown',
];

/**
 * Get intent description
 */
export function getIntentDescription(intent: SecurityIntent): string {
  const pattern = INTENT_PATTERNS.find(p => p.intent === intent);
  return pattern?.description || 'Unknown security intent';
}

/**
 * Get intent keywords
 */
export function getIntentKeywords(intent: SecurityIntent): string[] {
  const pattern = INTENT_PATTERNS.find(p => p.intent === intent);
  return pattern?.keywords || [];
}
