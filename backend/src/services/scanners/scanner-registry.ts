/**
 * Scanner Audit Registry
 *
 * Static metadata for each scanner tool used in audit evidence reporting.
 * Provides auditors with details about what each tool checks, its methodology,
 * and which security standards/frameworks it maps to.
 */

export interface ScannerAuditMeta {
  /** Human-readable tool name */
  displayName: string;
  /** Scanner category */
  category: string;
  /** What the tool does */
  description: string;
  /** Specific checks/rules the tool performs */
  checksPerformed: string[];
  /** What files/targets the tool analyzes */
  scanScope: string;
  /** How the tool performs its analysis */
  methodology: string;
  /** Security standards and frameworks this tool maps to */
  standards: string[];
}

export const SCANNER_REGISTRY: Record<string, ScannerAuditMeta> = {
  // -- SAST ---------------------------------------------------------------
  opengrep: {
    displayName: 'OpenGrep (Semgrep)',
    category: 'SAST',
    description: 'Multi-language static analysis for security vulnerabilities',
    checksPerformed: [
      'Injection vulnerabilities (SQL, OS command, LDAP)',
      'Cross-site scripting (XSS) patterns',
      'Insecure deserialization',
      'Hardcoded credentials and secrets',
      'Insecure cryptographic usage',
      'Authentication and session management flaws',
      'OWASP Top 10 rule coverage',
      'Security audit rules',
    ],
    scanScope: 'All source code files (Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C, C++)',
    methodology: 'Pattern-based static analysis using Semgrep rule engine with auto, security-audit, owasp-top-ten, and secrets rulesets. Matches AST patterns against known vulnerability signatures.',
    standards: ['OWASP Top 10', 'CWE Top 25', 'SANS Top 25'],
  },

  bandit: {
    displayName: 'Bandit',
    category: 'SAST',
    description: 'Python-specific security linter for common vulnerabilities',
    checksPerformed: [
      'SQL injection via string formatting',
      'Shell injection via subprocess calls',
      'Use of insecure hash functions (MD5, SHA1)',
      'Hardcoded passwords and secrets',
      'Use of assert in production code',
      'Insecure temp file creation',
      'Binding to all interfaces (0.0.0.0)',
      'Unsafe dynamic code execution with untrusted input',
      'Insecure SSL/TLS configuration',
      'Weak cryptographic key sizes',
    ],
    scanScope: 'Python source files (.py) excluding node_modules, venv, __pycache__',
    methodology: 'AST-based analysis of Python source code. Parses each file into an abstract syntax tree and applies security-focused test plugins (B1xx-B7xx series) with medium+ severity and confidence filtering.',
    standards: ['OWASP Top 10', 'CWE', 'PEP 506'],
  },

  gosec: {
    displayName: 'Gosec',
    category: 'SAST',
    description: 'Go source code security analyzer',
    checksPerformed: [
      'SQL injection in database queries',
      'Command injection via exec package',
      'Path traversal vulnerabilities',
      'Insecure TLS configurations',
      'Hardcoded credentials',
      'Use of weak random number generators',
      'Integer overflow risks',
      'Unsafe pointer usage',
      'File permission issues',
    ],
    scanScope: 'Go source files (.go) in the project directory',
    methodology: 'AST-based static analysis of Go source code using gosec rules (G1xx-G6xx). Inspects function calls, variable assignments, and control flow for security anti-patterns.',
    standards: ['OWASP Top 10', 'CWE', 'Go Security Best Practices'],
  },

  'eslint-security': {
    displayName: 'ESLint Security',
    category: 'SAST',
    description: 'JavaScript/TypeScript security linting rules',
    checksPerformed: [
      'Dangerous dynamic code execution patterns',
      'Prototype pollution patterns',
      'Regular expression denial of service (ReDoS)',
      'Insecure random number generation',
      'DOM-based XSS via innerHTML/outerHTML',
      'Open redirect vulnerabilities',
      'Object injection via user-controlled keys',
      'Buffer size validation',
      'Non-literal require() calls',
    ],
    scanScope: 'JavaScript (.js, .jsx) and TypeScript (.ts, .tsx) source files',
    methodology: 'AST-based linting using eslint-plugin-security and eslint-plugin-no-unsanitized rule sets. Analyzes code patterns for known JavaScript/TypeScript security vulnerabilities.',
    standards: ['OWASP Top 10', 'CWE', 'Node.js Security Checklist'],
  },

  pmd: {
    displayName: 'PMD',
    category: 'SAST',
    description: 'Multi-language static analysis for code quality and security',
    checksPerformed: [
      'Empty catch blocks hiding errors',
      'Unused variables and imports',
      'Overly complex methods (cyclomatic complexity)',
      'Resource leak detection',
      'Security-sensitive API misuse',
      'Code duplication (CPD)',
      'Design issues and anti-patterns',
    ],
    scanScope: 'Java, JavaScript, XML, Apex, Scala, and other supported language source files',
    methodology: 'Rule-based static analysis using PMD rule sets. Parses source code AST and applies configurable rules for code quality, security, and best practices.',
    standards: ['CWE', 'CERT Coding Standards'],
  },

  // -- DAST ---------------------------------------------------------------
  nuclei: {
    displayName: 'Nuclei',
    category: 'DAST',
    description: 'Dynamic application security testing with vulnerability templates',
    checksPerformed: [
      'CVE-based vulnerability detection',
      'Misconfiguration checks',
      'Default credential testing',
      'Exposed panel detection',
      'Technology fingerprinting',
      'WAF detection and bypass testing',
      'HTTP security header analysis',
      'SSL/TLS configuration assessment',
      'Information disclosure checks',
    ],
    scanScope: 'Web application endpoints, HTTP services, and network targets',
    methodology: 'Template-based scanning using YAML-defined vulnerability signatures. Sends crafted HTTP requests and analyzes responses to detect known vulnerabilities, misconfigurations, and exposures.',
    standards: ['OWASP Top 10', 'CVE Database', 'CWE'],
  },

  zap: {
    displayName: 'OWASP ZAP',
    category: 'DAST',
    description: 'Dynamic application security testing with active and passive scanning',
    checksPerformed: [
      'SQL injection (various techniques)',
      'Cross-site scripting (reflected, stored, DOM)',
      'Server-side request forgery (SSRF)',
      'Remote code execution',
      'Directory traversal',
      'Security header analysis',
      'Cookie security attributes',
      'CORS misconfiguration',
      'Authentication bypass testing',
    ],
    scanScope: 'Web application URLs, APIs, and HTTP endpoints',
    methodology: 'Proxy-based dynamic analysis. Spiders the application to discover endpoints, then performs passive analysis of responses and active scanning with attack payloads to detect runtime vulnerabilities.',
    standards: ['OWASP Top 10', 'OWASP ASVS', 'CWE', 'WASC'],
  },

  // -- SCA ----------------------------------------------------------------
  trivy: {
    displayName: 'Trivy',
    category: 'SCA',
    description: 'Comprehensive vulnerability scanner for containers, filesystems, and IaC',
    checksPerformed: [
      'Known vulnerability detection (CVE database)',
      'OS package vulnerability scanning',
      'Application dependency vulnerability scanning',
      'Container image misconfiguration checks',
      'Infrastructure-as-code misconfiguration detection',
      'Secret detection in files and images',
      'License compliance checking',
      'SBOM generation and analysis',
    ],
    scanScope: 'Package manifests (package.json, requirements.txt, go.mod, Gemfile, pom.xml), Dockerfiles, container images, IaC files (Terraform, CloudFormation, Kubernetes)',
    methodology: 'Scans filesystem for package manifests and lock files, matches installed packages against vulnerability databases (NVD, GitHub Advisory, vendor-specific). Also checks for misconfigurations and secrets using built-in rules.',
    standards: ['CVE/NVD', 'OWASP Top 10 (A06)', 'CIS Benchmarks', 'NIST SP 800-53'],
  },

  grype: {
    displayName: 'Grype',
    category: 'SCA',
    description: 'Dependency vulnerability scanner for containers and filesystems',
    checksPerformed: [
      'Known vulnerability detection (CVE database)',
      'OS package vulnerability analysis',
      'Application dependency vulnerability analysis',
      'Container image layer scanning',
      'Fixed version availability checking',
    ],
    scanScope: 'Package manifests, lock files, container images, and filesystem packages',
    methodology: 'Generates SBOM using Syft, then matches all identified packages against vulnerability databases (NVD, GitHub Advisories, OS vendor databases). Reports CVEs with severity, fix versions, and references.',
    standards: ['CVE/NVD', 'OWASP Top 10 (A06)', 'GHSA'],
  },

  // pip-audit removed: redundant with Trivy + Grype SCA coverage

  // -- Secrets ------------------------------------------------------------
  gitleaks: {
    displayName: 'Gitleaks',
    category: 'Secrets',
    description: 'Detects hardcoded secrets, API keys, and credentials in source code',
    checksPerformed: [
      'AWS access keys and secret keys',
      'GitHub/GitLab/Bitbucket tokens',
      'Private keys (RSA, SSH, PGP)',
      'Database connection strings',
      'API keys and tokens (generic patterns)',
      'OAuth client secrets',
      'JWT secrets and signing keys',
      'Cloud provider credentials (GCP, Azure)',
      'Password patterns in configuration files',
      'High-entropy string detection',
    ],
    scanScope: 'All files in repository including git history (redacted output for security)',
    methodology: 'Regex-based pattern matching against 150+ secret patterns with entropy analysis. Scans current file contents and optionally git commit history. Applies allowlists and custom rules to reduce false positives. Secrets are redacted in output.',
    standards: ['CWE-798', 'CWE-259', 'OWASP Top 10 (A07)'],
  },

  // detect-secrets removed: redundant with Gitleaks (superset coverage)

  // -- IaC ----------------------------------------------------------------
  checkov: {
    displayName: 'Checkov',
    category: 'IaC',
    description: 'Infrastructure-as-code security scanner',
    checksPerformed: [
      'Dockerfile security best practices (CIS Docker Benchmark)',
      'Terraform resource misconfigurations',
      'Kubernetes manifest security checks',
      'CloudFormation security validation',
      'Docker Compose security analysis',
      'Helm chart security checks',
      'ARM template validation',
      'Serverless framework checks',
    ],
    scanScope: 'Dockerfiles, docker-compose.yml, Terraform (.tf), Kubernetes YAML, CloudFormation templates, Helm charts',
    methodology: 'Graph-based static analysis of infrastructure-as-code files. Parses IaC definitions, builds resource graphs, and checks 1000+ built-in policies covering security, networking, encryption, and compliance.',
    standards: ['CIS Benchmarks', 'NIST SP 800-53', 'SOC 2', 'PCI-DSS', 'HIPAA'],
  },

  // -- Load Testing -------------------------------------------------------
  locust: {
    displayName: 'Locust',
    category: 'Load Testing',
    description: 'Python-based load testing framework',
    checksPerformed: [
      'Response time under load (p50, p95, p99)',
      'Throughput measurement (requests per second)',
      'Error rate under stress',
      'Concurrent user capacity',
      'Resource exhaustion detection',
    ],
    scanScope: 'Web application HTTP endpoints',
    methodology: 'Simulates concurrent users making HTTP requests against target endpoints. Measures response times, throughput, and error rates under configurable load patterns.',
    standards: ['OWASP Performance Testing'],
  },

  artillery: {
    displayName: 'Artillery',
    category: 'Load Testing',
    description: 'Modern load testing and performance measurement',
    checksPerformed: [
      'Response time percentiles (p50, p95, p99)',
      'Requests per second throughput',
      'Error rate and error distribution',
      'Connection timeout detection',
      'Latency degradation under load',
    ],
    scanScope: 'HTTP/HTTPS endpoints, WebSocket connections, and API endpoints',
    methodology: 'Scenario-based load testing with configurable arrival rates and duration. Generates detailed performance reports with latency distributions and error breakdowns.',
    standards: ['OWASP Performance Testing'],
  },

  // -- API Testing --------------------------------------------------------
  newman: {
    displayName: 'Newman (Postman)',
    category: 'API Testing',
    description: 'Postman collection runner for API testing',
    checksPerformed: [
      'API endpoint response validation',
      'Status code verification',
      'Response schema validation',
      'Authentication flow testing',
      'Error handling verification',
    ],
    scanScope: 'API endpoints defined in Postman collections',
    methodology: 'Executes Postman collections with test assertions. Validates response status codes, body content, headers, and response times against defined expectations.',
    standards: ['OpenAPI Specification', 'REST API Best Practices'],
  },

  pact: {
    displayName: 'Pact',
    category: 'API Testing',
    description: 'Consumer-driven contract testing',
    checksPerformed: [
      'API contract compliance verification',
      'Request/response schema validation',
      'Breaking change detection',
      'Provider state verification',
      'Content-type negotiation',
    ],
    scanScope: 'API contracts between consumer and provider services',
    methodology: 'Consumer-driven contract testing that verifies API interactions match agreed-upon contracts (pacts). Replays recorded interactions against the provider to detect breaking changes.',
    standards: ['Consumer-Driven Contracts', 'API Versioning Standards'],
  },

  restler: {
    displayName: 'RESTler',
    category: 'API Testing',
    description: 'Stateful REST API fuzzing tool',
    checksPerformed: [
      'API endpoint fuzzing for crashes',
      'Invalid input handling',
      'Authentication bypass detection',
      'Data leakage via error messages',
      'Resource exhaustion endpoints',
      'Sequence-dependent vulnerability detection',
    ],
    scanScope: 'REST API endpoints defined in OpenAPI/Swagger specifications',
    methodology: 'Stateful API fuzzing that infers producer-consumer dependencies between API operations. Automatically generates and executes test sequences with fuzzed parameters to discover security vulnerabilities.',
    standards: ['OWASP API Security Top 10', 'CWE'],
  },

  // -- Browser/Visual -----------------------------------------------------
  playwright: {
    displayName: 'Playwright',
    category: 'Browser Testing',
    description: 'End-to-end browser testing framework',
    checksPerformed: [
      'Functional UI flow validation',
      'Cross-browser compatibility',
      'JavaScript error detection',
      'Network request validation',
      'Visual regression detection',
    ],
    scanScope: 'Web application pages and user flows in Chromium, Firefox, and WebKit',
    methodology: 'Automated browser testing that navigates through application flows, executing user actions and asserting expected outcomes. Captures screenshots and traces for failure analysis.',
    standards: ['WCAG', 'W3C Web Standards'],
  },

  backstop: {
    displayName: 'BackstopJS',
    category: 'Visual Testing',
    description: 'Visual regression testing for web UIs',
    checksPerformed: [
      'Visual diff detection between reference and test',
      'Responsive layout verification',
      'CSS regression detection',
      'Component rendering consistency',
    ],
    scanScope: 'Web page screenshots at configurable viewports and selectors',
    methodology: 'Captures screenshots of web pages at specified URLs and viewports, then performs pixel-level comparison against reference images to detect visual regressions.',
    standards: ['Visual QA Standards'],
  },

  pa11y: {
    displayName: 'Pa11y',
    category: 'Accessibility',
    description: 'Automated accessibility testing',
    checksPerformed: [
      'WCAG 2.1 Level A compliance',
      'WCAG 2.1 Level AA compliance',
      'Color contrast ratio validation',
      'ARIA attribute correctness',
      'Form label associations',
      'Image alt text presence',
      'Keyboard navigation support',
      'Heading hierarchy validation',
    ],
    scanScope: 'Web page HTML rendered in headless browser',
    methodology: 'Automated accessibility auditing using HTML_CodeSniffer or axe-core. Loads pages in a headless browser and checks against WCAG 2.1 guidelines, reporting violations by severity level.',
    standards: ['WCAG 2.1', 'Section 508', 'ADA Compliance'],
  },

  // -- Supply Chain -------------------------------------------------------
  syft: {
    displayName: 'Syft',
    category: 'SBOM',
    description: 'Software bill of materials generator',
    checksPerformed: [
      'Package identification and cataloging',
      'Dependency tree resolution',
      'License identification',
      'Package version enumeration',
      'Multi-ecosystem package discovery',
    ],
    scanScope: 'Container images, filesystems, and archives. Detects packages across npm, pip, gem, cargo, go modules, Maven, NuGet, and more.',
    methodology: 'Catalogs software packages by parsing package manifests, lock files, and installed package databases. Generates standardized SBOM in CycloneDX or SPDX format for supply chain visibility.',
    standards: ['NTIA SBOM Minimum Elements', 'CycloneDX', 'SPDX', 'Executive Order 14028'],
  },

  'in-toto': {
    displayName: 'in-toto',
    category: 'Supply Chain',
    description: 'Software supply chain integrity framework',
    checksPerformed: [
      'Build step verification',
      'Supply chain layout compliance',
      'Artifact integrity validation',
      'Step ordering verification',
      'Authorized functionary checks',
    ],
    scanScope: 'Build pipeline artifacts, step metadata, and layout definitions',
    methodology: 'Verifies that each step in the software supply chain was performed by an authorized entity and that the resulting artifacts match expected specifications defined in the supply chain layout.',
    standards: ['SLSA', 'in-toto Specification', 'Executive Order 14028'],
  },

  cosign: {
    displayName: 'Cosign (Sigstore)',
    category: 'Supply Chain',
    description: 'Container image signing and verification',
    checksPerformed: [
      'Container image signature verification',
      'Keyless signing via OIDC',
      'Transparency log recording (Rekor)',
      'Certificate-based identity verification',
      'Image digest validation',
    ],
    scanScope: 'Container images in OCI registries',
    methodology: 'Signs container images using Sigstore keyless signing (backed by Fulcio CA and Rekor transparency log) or traditional key pairs. Verifies signatures against trust policies.',
    standards: ['Sigstore', 'SLSA', 'TUF', 'Executive Order 14028'],
  },

  // -- Policy & Reporting -------------------------------------------------
  opa: {
    displayName: 'Open Policy Agent',
    category: 'Policy',
    description: 'General-purpose policy engine',
    checksPerformed: [
      'Custom security policy assessment',
      'Resource configuration validation',
      'Access control policy checks',
      'Compliance rule enforcement',
    ],
    scanScope: 'Rego policy files (.rego) and data files against structured input',
    methodology: 'Assesses structured data against declarative Rego policies. Policies define allow/deny rules that can enforce security, compliance, and operational requirements.',
    standards: ['Custom Policy Frameworks', 'NIST SP 800-53'],
  },

  conftest: {
    displayName: 'Conftest',
    category: 'Policy',
    description: 'Policy testing for structured configuration data',
    checksPerformed: [
      'Configuration file policy compliance',
      'YAML/JSON/HCL policy validation',
      'Dockerfile policy enforcement',
      'Kubernetes manifest policy checks',
    ],
    scanScope: 'Structured configuration files (YAML, JSON, HCL, Dockerfile, etc.) in the policy/ directory',
    methodology: 'Tests structured configuration files against Rego policies using OPA engine. Enables organization-specific policy enforcement for infrastructure and application configurations.',
    standards: ['Custom Policy Frameworks', 'CIS Benchmarks'],
  },

  allure: {
    displayName: 'Allure',
    category: 'Reporting',
    description: 'Test report generation framework',
    checksPerformed: [
      'Test result aggregation and reporting',
      'Test execution timeline',
      'Failure categorization',
      'Test suite trend analysis',
    ],
    scanScope: 'Test results from various testing frameworks',
    methodology: 'Aggregates test results from multiple sources and generates interactive HTML reports with detailed test execution data, failure analysis, and historical trends.',
    standards: ['Test Reporting Standards'],
  },

  // garak removed: config-detection-only mode provides minimal value
  // llm-guard removed: no scanner file or SCANNER_MAP entry exists

  // -- API Mock / Chaos / Migration / Load --------------------------------
  wiremock: {
    displayName: 'WireMock',
    category: 'API Testing',
    description: 'API mock and stub security analysis',
    checksPerformed: [
      'Hardcoded secrets in stub responses',
      'Overly permissive URL pattern matching',
      'Sensitive data returned without auth checks',
      'Mock configuration security review',
    ],
    scanScope: 'WireMock mapping JSON files in mappings/ and __files/ directories',
    methodology: 'Static analysis of WireMock stub definitions. Parses JSON mapping files to detect hardcoded credentials, overly permissive URL patterns, and stubs that return sensitive data without requiring authentication.',
    standards: ['OWASP Top 10 (A07)', 'CWE-798', 'CWE-862'],
  },

  falco: {
    displayName: 'Falco',
    category: 'Runtime Security',
    description: 'Runtime security rule analysis for container workloads',
    checksPerformed: [
      'Disabled critical security rules',
      'Overly broad rule conditions',
      'Missing priority assignments',
      'Runtime monitoring coverage gaps',
    ],
    scanScope: 'Falco YAML rule files',
    methodology: 'Static analysis of Falco rule definitions. Checks for disabled critical rules, overly broad conditions that cause alert fatigue, and missing priority assignments.',
    standards: ['CIS Benchmarks', 'NIST SP 800-53 (AU)', 'MITRE ATT&CK'],
  },

  toxiproxy: {
    displayName: 'Toxiproxy',
    category: 'Chaos Testing',
    description: 'Chaos/resilience testing configuration analysis',
    checksPerformed: [
      'Hardcoded service addresses',
      'Missing chaos testing for critical dependencies',
      'Configuration portability issues',
    ],
    scanScope: 'Toxiproxy configuration files and docker-compose definitions',
    methodology: 'Analyzes Toxiproxy configuration for hardcoded hostnames, missing resilience test coverage for database and service dependencies, and configuration portability issues.',
    standards: ['Netflix Chaos Engineering Principles', 'OWASP Resilience Testing'],
  },

  flyway: {
    displayName: 'Flyway',
    category: 'Database Security',
    description: 'Database migration security analysis',
    checksPerformed: [
      'Privilege escalation in migrations (GRANT ALL, SUPERUSER)',
      'Hardcoded credentials in SQL files',
      'Unsafe DROP statements without IF EXISTS',
      'SELECT * in data migrations',
      'Missing transaction wrapping for DDL',
    ],
    scanScope: 'SQL migration files (Flyway, Knex, Drizzle, Prisma, generic SQL)',
    methodology: 'Static analysis of SQL migration files. Pattern matches for privilege escalation, hardcoded credentials, unsafe DDL operations, and missing transaction safety.',
    standards: ['CWE-250', 'CWE-798', 'OWASP Top 10 (A01, A07)', 'CIS Database Benchmarks'],
  },

  gatling: {
    displayName: 'Gatling',
    category: 'Load Testing',
    description: 'Load test results analysis for performance and reliability',
    checksPerformed: [
      'Error rate under load (>5% threshold)',
      'Response time percentiles (p99 >5s threshold)',
      'Per-endpoint failure analysis',
      'Simulation log error patterns',
    ],
    scanScope: 'Gatling stats.json reports, simulation.log files, and Scala simulation definitions',
    methodology: 'Analyzes Gatling load test output for error rates exceeding thresholds, slow response times, and per-endpoint failure patterns. Flags reliability issues discovered during load testing.',
    standards: ['OWASP Performance Testing', 'SRE Reliability Principles'],
  },

  // -- Additional SCA & Container -----------------------------------------
  dockle: {
    displayName: 'Dockle',
    category: 'Container',
    description: 'Container image linter for CIS Docker benchmarks',
    checksPerformed: [
      'CIS Docker Benchmark compliance',
      'Container user privilege checks',
      'HEALTHCHECK instruction presence',
      'Content trust verification',
      'Sensitive file detection in images',
      'Package manager cache cleanup',
      'Multi-stage build best practices',
    ],
    scanScope: 'Container images (Docker, OCI format)',
    methodology: 'Inspects container image layers and metadata against CIS Docker Benchmark best practices. Checks for security issues including running as root, missing health checks, and sensitive file exposure.',
    standards: ['CIS Docker Benchmark', 'Docker Security Best Practices'],
  },

  // -- AI Code Quality -----------------------------------------------------
  'package-validator': {
    displayName: 'Package Validator',
    category: 'AI Code Quality',
    description: 'Detects hallucinated (non-existent) packages in dependency files',
    checksPerformed: [
      'npm registry existence validation',
      'PyPI registry existence validation',
      'Go module proxy existence validation',
      'Slopsquatting attack vector detection',
      'Hallucinated dependency identification',
    ],
    scanScope: 'Dependency files (package.json, requirements.txt, go.mod) validated against package registries',
    methodology: 'Parses dependency manifests and validates each package exists in its respective registry (npm, PyPI, Go proxy) via HTTP HEAD requests. Non-existent packages are flagged as hallucinated — a common AI code generation artifact that creates supply chain attack vectors.',
    standards: ['CWE-829', 'OWASP A08:2021', 'SLSA Supply Chain Security'],
  },

  jest: {
    displayName: 'Jest',
    category: 'Test Runners',
    description: 'JavaScript/TypeScript test execution and coverage analysis',
    checksPerformed: [
      'Jest test suite execution',
      'Test failure detection and reporting',
      'Suite-level error detection (syntax, import failures)',
      'Statement coverage analysis',
      'Test pass rate calculation',
    ],
    scanScope: 'JavaScript and TypeScript test files (*.test.ts, *.test.js, *.spec.ts, *.spec.js)',
    methodology: 'Executes the full Jest test suite with coverage collection. Reports test failures and suite errors as findings. Coverage data informs the quality score bonus system.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  pytest: {
    displayName: 'pytest',
    category: 'Test Runners',
    description: 'Python test execution and coverage analysis',
    checksPerformed: [
      'pytest test execution',
      'Test failure and error detection',
      'Collection error detection (syntax, import failures)',
      'Statement coverage analysis via pytest-cov',
      'Test pass rate calculation',
    ],
    scanScope: 'Python test files (test_*.py, *_test.py) with associated source code',
    methodology: 'Executes the full pytest test suite with coverage collection via pytest-cov. Reports test failures, errors, and collection problems as findings. Coverage data informs the quality score bonus system.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  'selenium-gen': {
    displayName: 'Selenium Test Generator',
    category: 'Test Generation',
    description: 'Generates Selenium WebDriver test files from code analysis (endpoints, auth patterns, data flows)',
    checksPerformed: [
      'Endpoint analysis for functional E2E test generation',
      'Auth pattern analysis for auth bypass test generation',
      'Dataflow analysis for XSS and SQL injection test generation',
      'CSRF protection validation test generation',
    ],
    scanScope: 'Web application endpoints and security attack surface',
    methodology: 'Code analysis (CA-001 through CA-005) extracts endpoints, auth patterns, and data flows. Templates generate Selenium WebDriver + Mocha test suites targeting discovered attack surface with OWASP-mapped security payloads.',
    standards: ['OWASP Top 10', 'OWASP Testing Guide v4', 'CWE Top 25'],
  },

  stryker: {
    displayName: 'Stryker Mutator',
    category: 'AI Code Quality',
    description: 'JavaScript/TypeScript mutation testing for test quality validation',
    checksPerformed: [
      'Code mutation generation (arithmetic, logical, string, conditional)',
      'Test suite mutation detection rate',
      'Survived mutant identification per file',
      'Mutation score calculation',
      'Test quality gap detection',
    ],
    scanScope: 'JavaScript and TypeScript source files with associated test suites',
    methodology: 'Introduces code mutations (changing operators, removing statements, altering conditions) and runs the test suite against each mutation. Survived mutations indicate test quality gaps where code changes go undetected.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  mutmut: {
    displayName: 'mutmut',
    category: 'AI Code Quality',
    description: 'Python mutation testing for test quality validation',
    checksPerformed: [
      'Python source code mutation generation',
      'Test suite mutation detection rate',
      'Survived mutant identification',
      'Mutation score calculation',
      'Test assertion quality validation',
    ],
    scanScope: 'Python source files (.py) with associated pytest/unittest test suites',
    methodology: 'Mutates Python source code (changing operators, constants, return values) and runs the test suite. Survived mutations reveal weak test assertions that fail to catch logic changes — common in AI-generated tests that achieve high coverage but low mutation scores.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  pitest: {
    displayName: 'PIT (Pitest)',
    category: 'AI Code Quality',
    description: 'Java/JVM mutation testing for test quality validation',
    checksPerformed: [
      'Java bytecode mutation generation',
      'Test suite mutation kill rate',
      'Survived mutant identification per class/method',
      'Mutation score calculation',
      'No-coverage mutant detection',
    ],
    scanScope: 'Java source files with JUnit/TestNG test suites, built via Maven or Gradle',
    methodology: 'Generates bytecode-level mutations in Java classes and runs the test suite to determine which mutations are detected (killed) vs undetected (survived). Reports mutation scores per class to identify undertested code.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  scancode: {
    displayName: 'ScanCode Toolkit',
    category: 'AI Code Quality',
    description: 'Snippet-level license detection for copyleft contamination',
    checksPerformed: [
      'GPL/AGPL license pattern detection in source code',
      'LGPL license pattern detection',
      'SSPL/EUPL/CPAL copyleft detection',
      'License confidence scoring',
      'AI-generated code license contamination assessment',
    ],
    scanScope: 'All source files scanned for embedded license patterns and code snippets matching known licensed code',
    methodology: 'Uses ScanCode Toolkit to perform snippet-level license detection across source files. Matches code patterns against a database of known licensed code with confidence scoring. Flags copyleft licenses (GPL, AGPL, LGPL, SSPL) that could contaminate proprietary codebases — a risk amplified by AI code generation.',
    standards: ['SPDX License List', 'OSI Approved Licenses', 'SBOM Requirements'],
  },

  schemathesis: {
    displayName: 'Schemathesis',
    category: 'AI Code Quality',
    description: 'Schema-driven API testing and validation for OpenAPI specifications',
    checksPerformed: [
      'OpenAPI/Swagger schema validation',
      'Endpoint fuzz testing via property-based generation',
      'Server error detection (5xx responses)',
      'Input validation bypass testing',
      'Security definition completeness check',
    ],
    scanScope: 'OpenAPI/Swagger specification files and their defined API endpoints',
    methodology: 'Validates OpenAPI specifications for correctness and uses property-based testing (Hypothesis) to generate API requests that explore edge cases. Detects schema violations, unhandled server errors, and missing security definitions — common issues in AI-generated API specs.',
    standards: ['OpenAPI 3.x Specification', 'OWASP API Security Top 10', 'CWE-20'],
  },

  aflpp: {
    displayName: 'AFL++',
    category: 'AI Code Quality',
    description: 'Coverage-guided fuzz testing for C/C++ memory safety. Note: Requires AFL++ package in Alpine repos. May not be available on all architectures.',
    checksPerformed: [
      'Coverage-guided fuzz testing',
      'Crash detection (buffer overflow, use-after-free, null deref)',
      'Hang detection (infinite loops, deadlocks)',
      'Input corpus generation and evolution',
      'Memory safety violation discovery',
    ],
    scanScope: 'C/C++ compiled binaries built from Makefile or CMake projects',
    methodology: 'Compiles C/C++ projects with AFL++ instrumentation (or uses QEMU mode for uninstrumented binaries) and runs coverage-guided fuzzing to discover crash-inducing inputs. Crashes indicate memory safety vulnerabilities common in AI-generated C/C++ code.',
    standards: ['CWE-120', 'CWE-416', 'CWE-476', 'CWE-835', 'CERT C Coding Standard'],
  },

  // -- Code Quality & Dead Code -------------------------------------------
  knip: {
    displayName: 'Knip',
    category: 'Code Quality',
    description: 'Dead code detection for JavaScript/TypeScript projects',
    checksPerformed: ['Unused file detection', 'Unused dependency detection', 'Unlisted dependency detection', 'Unused export detection'],
    scanScope: 'JavaScript/TypeScript project files, package.json dependencies',
    methodology: 'Analyzes the dependency graph of JS/TS projects to find unused files, exports, dependencies, and types. Identifies dead code that increases maintenance burden and attack surface.',
    standards: ['CWE-1164', 'OWASP A06:2021'],
  },

  oxlint: {
    displayName: 'Oxlint',
    category: 'Code Quality',
    description: 'High-performance JavaScript/TypeScript linter',
    checksPerformed: ['Code correctness checks', 'Suspicious code detection', 'Performance anti-patterns', 'Import/export validation'],
    scanScope: 'JavaScript (.js, .jsx) and TypeScript (.ts, .tsx) source files',
    methodology: 'Rust-based linter that performs AST analysis of JS/TS files at high speed. Detects correctness issues, suspicious patterns, and performance anti-patterns.',
    standards: ['CWE', 'ESLint Core Rules'],
  },

  jscpd: {
    displayName: 'jscpd',
    category: 'Code Quality',
    description: 'Cross-language copy-paste detection',
    checksPerformed: ['Cross-file duplicate detection', 'Code clone identification', 'Duplication percentage calculation'],
    scanScope: 'All source files across supported languages',
    methodology: 'Token-based analysis to detect copy-pasted code blocks across files and languages. Reports duplication percentage and identifies specific cloned regions.',
    standards: ['ISO/IEC 25010 (Maintainability)'],
  },

  ruff: {
    displayName: 'Ruff',
    category: 'Code Quality',
    description: 'High-performance Python linter and formatter',
    checksPerformed: ['Pyflakes error detection', 'Pycodestyle violations', 'flake8-bandit security checks', 'isort import ordering', 'pep8-naming', 'pyupgrade modernization', 'flake8-bugbear'],
    scanScope: 'Python source files (.py)',
    methodology: 'Rust-based Python linter implementing 800+ rules from flake8, pylint, isort, and others. 10-100x faster than traditional Python linters.',
    standards: ['PEP 8', 'PEP 257', 'CWE', 'OWASP Top 10'],
  },

  phpstan: {
    displayName: 'PHPStan',
    category: 'SAST',
    description: 'PHP static analysis tool',
    checksPerformed: ['Type checking', 'Dead code detection', 'Undefined variable access', 'Missing return types', 'Unreachable code'],
    scanScope: 'PHP source files (.php)',
    methodology: 'Static analysis of PHP code using type inference and control flow analysis. Detects bugs, type errors, and unreachable code at configurable strictness levels.',
    standards: ['CWE', 'PHP-FIG PSR Standards'],
  },

  typos: {
    displayName: 'typos',
    category: 'Code Quality',
    description: 'Source code spell checker',
    checksPerformed: ['Identifier spell checking', 'String literal spell checking', 'Comment spell checking', 'Filename spell checking'],
    scanScope: 'All text files in the project',
    methodology: 'Fast, low-false-positive spell checker designed for source code. Checks identifiers, strings, and comments against a curated dictionary.',
    standards: ['ISO/IEC 25010 (Maintainability)'],
  },

  libyear: {
    displayName: 'Libyear',
    category: 'SCA',
    description: 'Dependency freshness scoring',
    checksPerformed: ['npm dependency version gap analysis', 'pip dependency version gap analysis', 'Major version behind detection'],
    scanScope: 'package.json, requirements.txt, pyproject.toml dependencies',
    methodology: 'Checks installed dependency versions against latest available versions. Flags packages that are multiple major versions behind, indicating increased risk of missing security patches.',
    standards: ['CWE-1104', 'OWASP A06:2021'],
  },

  vale: {
    displayName: 'Vale',
    category: 'Code Quality',
    description: 'Documentation prose linter',
    checksPerformed: ['Spelling validation', 'Grammar checking', 'Style guide enforcement', 'Readability scoring'],
    scanScope: 'Markdown (.md), reStructuredText (.rst), AsciiDoc (.adoc) files',
    methodology: 'Rule-based prose linting using configurable style guides. Checks documentation for spelling, grammar, consistency, and readability.',
    standards: ['Technical Writing Best Practices'],
  },

  // -- CI/CD & Infrastructure Security ------------------------------------
  actionlint: {
    displayName: 'actionlint',
    category: 'CI/CD Security',
    description: 'GitHub Actions workflow linter',
    checksPerformed: ['Workflow syntax validation', 'Action version pinning checks', 'Shell script validation', 'Expression type checking', 'Permissions analysis'],
    scanScope: '.github/workflows/*.yml files',
    methodology: 'Static analysis of GitHub Actions workflow files. Validates syntax, checks for unpinned action versions, analyzes shell scripts for errors, and verifies expression types.',
    standards: ['GitHub Actions Security Best Practices', 'CWE-78'],
  },

  poutine: {
    displayName: 'Poutine',
    category: 'CI/CD Security',
    description: 'CI/CD pipeline security analyzer',
    checksPerformed: ['Pipeline injection detection', 'Untrusted code execution', 'Secret exposure in logs', 'Excessive permissions', 'Unpinned dependencies', 'Debug mode detection'],
    scanScope: 'GitHub Actions, GitLab CI, Azure Pipelines configuration files',
    methodology: 'Analyzes CI/CD pipeline definitions for security misconfigurations, injection vulnerabilities, and excessive permissions that could lead to supply chain attacks.',
    standards: ['OWASP CI/CD Top 10', 'CWE-78', 'SLSA'],
  },

  scorecard: {
    displayName: 'OpenSSF Scorecard',
    category: 'Supply Chain',
    description: 'Repository security health assessment',
    checksPerformed: ['Branch protection analysis', 'Code review policy', 'Dependency update tooling', 'Fuzzing coverage', 'License detection', 'Pinned dependencies', 'SAST usage', 'Security policy', 'Signed releases', 'Token permissions', 'Vulnerability disclosure'],
    scanScope: 'Repository-level security practices and configurations',
    methodology: 'Evaluates open-source project security practices against 18 checks defined by the OpenSSF. Each check scores 0-10 based on automated analysis of repository metadata, CI configuration, and security tooling.',
    standards: ['OpenSSF Scorecard', 'SLSA', 'NIST SSDF'],
  },

  kubeconform: {
    displayName: 'Kubeconform',
    category: 'IaC',
    description: 'Kubernetes manifest validation',
    checksPerformed: ['K8s API schema validation', 'Resource definition correctness', 'API version compatibility'],
    scanScope: 'Kubernetes YAML manifests',
    methodology: 'Validates Kubernetes manifests against official API schemas. Detects invalid resource definitions, incorrect field types, and deprecated API versions.',
    standards: ['Kubernetes API Specification', 'CIS Kubernetes Benchmark'],
  },

  'kube-linter': {
    displayName: 'KubeLinter',
    category: 'IaC',
    description: 'Kubernetes security linting',
    checksPerformed: ['Container privilege escalation checks', 'Resource limit enforcement', 'Security context validation', 'Network policy assessment', 'Pod security standards'],
    scanScope: 'Kubernetes YAML manifests and Helm charts',
    methodology: 'Analyzes Kubernetes manifests for security misconfigurations, missing resource limits, and privilege escalation risks. Checks against security best practices.',
    standards: ['CIS Kubernetes Benchmark', 'NSA Kubernetes Hardening Guide', 'Pod Security Standards'],
  },

  // -- API & License Compliance -------------------------------------------
  spectral: {
    displayName: 'Spectral',
    category: 'API Testing',
    description: 'OpenAPI/AsyncAPI specification linter',
    checksPerformed: ['OpenAPI schema validation', 'API design rule enforcement', 'Security definition completeness', 'Description quality', 'Naming convention checks'],
    scanScope: 'OpenAPI (Swagger) and AsyncAPI specification files',
    methodology: 'Validates API specifications against configurable rulesets. Checks for schema correctness, security definition completeness, and API design best practices.',
    standards: ['OpenAPI 3.x Specification', 'AsyncAPI Specification'],
  },

  'dotenv-linter': {
    displayName: 'dotenv-linter',
    category: 'Code Quality',
    description: '.env file validation and linting',
    checksPerformed: ['Duplicate key detection', 'Incorrect delimiter usage', 'Extra blank line detection', 'Key ordering check', 'Leading character validation', 'Quote consistency', 'Space around equals', 'Trailing whitespace', 'Value substitution'],
    scanScope: '.env, .env.local, .env.development, .env.production files',
    methodology: 'Validates .env files for common issues like duplicate keys, inconsistent formatting, and potential data loss from overwritten variables.',
    standards: ['12-Factor App (Config)'],
  },

  'cargo-audit': {
    displayName: 'cargo-audit',
    category: 'SCA',
    description: 'Rust dependency vulnerability scanner',
    checksPerformed: ['RustSec advisory database lookup', 'Cargo.lock vulnerability scanning', 'Yanked crate detection'],
    scanScope: 'Rust Cargo.lock dependency files',
    methodology: 'Audits Rust dependencies against the RustSec Advisory Database. Identifies known vulnerabilities, yanked crates, and provides CVSS scores and fix recommendations.',
    standards: ['RustSec Advisory Database', 'CVE/NVD', 'CWE'],
  },

  'license-finder': {
    displayName: 'LicenseFinder',
    category: 'License Compliance',
    description: 'Multi-ecosystem license compliance detection',
    checksPerformed: ['Copyleft license detection (GPL, AGPL, SSPL)', 'Restrictive license detection (LGPL, MPL, EPL)', 'Unknown license flagging', 'License policy enforcement'],
    scanScope: 'All package manifests (npm, pip, gem, go, maven, cargo, composer)',
    methodology: 'Identifies licenses of all project dependencies across multiple ecosystems. Flags copyleft and restrictive licenses that may conflict with proprietary distribution models.',
    standards: ['SPDX License List', 'OSI Approved Licenses', 'FOSSA Compliance'],
  },

  cdxgen: {
    displayName: 'cdxgen',
    category: 'SBOM',
    description: 'CycloneDX SBOM generator with vulnerability detection',
    checksPerformed: ['Multi-ecosystem dependency enumeration', 'CycloneDX SBOM generation', 'Vulnerability detection from advisory databases', 'Component license extraction'],
    scanScope: 'All package manifests and lock files across npm, pip, go, maven, cargo, and more',
    methodology: 'Generates CycloneDX Software Bill of Materials by analyzing package manifests. Optionally includes vulnerability data from advisory databases. Complements Syft SPDX generation.',
    standards: ['CycloneDX', 'NTIA SBOM Minimum Elements', 'Executive Order 14028'],
  },

  // -- v2 Additions ----------------------------------------------------------

  lychee: {
    displayName: 'Lychee',
    category: 'Code Quality',
    description: 'Async broken link checker for documentation and HTML files',
    checksPerformed: ['Broken link detection', 'Timeout detection', 'DNS resolution errors'],
    scanScope: 'Markdown, HTML, and reStructuredText files',
    methodology: 'Asynchronous link checking with configurable concurrency. Validates URLs, file paths, and anchors in documentation and HTML files. Reports broken, redirected, and timed-out links.',
    standards: ['W3C Link Checker', 'ISO/IEC 25010 (Maintainability)'],
  },

  'axe-core': {
    displayName: 'axe-core',
    category: 'Accessibility',
    description: 'WCAG 2.1 accessibility testing engine',
    checksPerformed: ['WCAG 2.1 Level A compliance', 'WCAG 2.1 Level AA compliance', 'Color contrast validation', 'ARIA attribute correctness', 'Keyboard navigation support', 'Form label associations'],
    scanScope: 'Web page DOM rendered in headless browser',
    methodology: 'Injects axe-core accessibility engine into rendered pages and runs automated WCAG 2.1 checks. Reports violations with impact severity, affected elements, and remediation guidance.',
    standards: ['WCAG 2.1', 'Section 508', 'ADA Compliance', 'EN 301 549'],
  },

  c8: {
    displayName: 'c8',
    category: 'Testing',
    description: 'Native V8 code coverage collection',
    checksPerformed: ['Statement coverage analysis', 'Branch coverage analysis', 'Function coverage analysis', 'Uncovered line identification'],
    scanScope: 'JavaScript and TypeScript source files executed via Node.js',
    methodology: 'Uses V8 built-in code coverage instrumentation to collect coverage data without source transformation. Reports statement, branch, and function coverage with uncovered line details.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  'fast-check': {
    displayName: 'fast-check',
    category: 'Testing',
    description: 'Property-based testing framework for JavaScript/TypeScript',
    checksPerformed: ['Property invariant verification', 'Edge case generation', 'Shrinking of failing inputs', 'Arbitrary data generation'],
    scanScope: 'JavaScript and TypeScript test suites using fast-check arbitraries',
    methodology: 'Generates random inputs based on property specifications and verifies that stated invariants hold. Automatically shrinks failing inputs to minimal reproducing cases.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  hypothesis: {
    displayName: 'Hypothesis',
    category: 'Testing',
    description: 'Property-based testing framework for Python',
    checksPerformed: ['Property invariant verification', 'Edge case discovery', 'Failing input minimization', 'Stateful testing'],
    scanScope: 'Python test suites using Hypothesis strategies and decorators',
    methodology: 'Generates test inputs from configurable strategies and verifies that properties hold across all generated examples. Minimizes failing cases and maintains a database of known failures.',
    standards: ['IEEE 1008', 'ISO/IEC 29119 (Software Testing)'],
  },

  sqlmap: {
    displayName: 'sqlmap',
    category: 'DAST',
    description: 'Automated SQL injection detection and exploitation tool',
    checksPerformed: ['Boolean-based blind SQL injection', 'Time-based blind SQL injection', 'Error-based SQL injection', 'UNION query SQL injection', 'Stacked queries injection', 'Database fingerprinting'],
    scanScope: 'Web application URLs with query parameters and form inputs',
    methodology: 'Automated testing of URL parameters and form fields for SQL injection vulnerabilities using multiple injection techniques. Fingerprints the backend DBMS and enumerates database structure.',
    standards: ['OWASP Top 10 (A03)', 'CWE-89', 'OWASP Testing Guide'],
  },

  dalfox: {
    displayName: 'Dalfox',
    category: 'DAST',
    description: 'XSS vulnerability scanner and parameter analysis tool',
    checksPerformed: ['Reflected XSS detection', 'Stored XSS detection', 'DOM-based XSS detection', 'Parameter analysis', 'WAF bypass testing', 'Blind XSS testing'],
    scanScope: 'Web application URLs and HTTP parameters',
    methodology: 'Analyzes URL parameters for XSS injection points using payload generation, reflection analysis, and DOM event handler testing. Includes WAF fingerprinting and bypass techniques.',
    standards: ['OWASP Top 10 (A03)', 'CWE-79', 'CWE-80'],
  },

  ffuf: {
    displayName: 'ffuf',
    category: 'DAST',
    description: 'Fast web fuzzer for content discovery and endpoint enumeration',
    checksPerformed: ['Directory and file discovery', 'Virtual host enumeration', 'Parameter fuzzing', 'Endpoint brute-forcing', 'Response filtering and analysis'],
    scanScope: 'Web application HTTP endpoints',
    methodology: 'High-speed HTTP fuzzing with configurable wordlists and response filtering. Discovers hidden directories, files, parameters, and virtual hosts through systematic enumeration.',
    standards: ['OWASP Testing Guide', 'CWE-538', 'CWE-548'],
  },

  socket: {
    displayName: 'Socket',
    category: 'Supply Chain',
    description: 'Supply chain attack detection for package ecosystems',
    checksPerformed: ['Typosquatting detection', 'Install script analysis', 'Network activity detection', 'Filesystem access analysis', 'Obfuscated code detection', 'Maintainer change tracking'],
    scanScope: 'npm, PyPI, and Go module dependencies',
    methodology: 'Deep package analysis that inspects install scripts, runtime behavior indicators, and metadata changes to detect supply chain attacks including typosquatting, dependency confusion, and malicious package takeovers.',
    standards: ['SLSA', 'OpenSSF Scorecard', 'CWE-829', 'Executive Order 14028'],
  },

  giskard: {
    displayName: 'Giskard',
    category: 'AI Security',
    description: 'LLM vulnerability testing and AI red teaming platform',
    checksPerformed: ['Prompt injection testing', 'Jailbreak detection', 'Bias and fairness evaluation', 'Hallucination detection', 'Data leakage testing', 'Toxicity assessment'],
    scanScope: 'LLM endpoints, chatbot APIs, and AI model interfaces',
    methodology: 'Automated red teaming of LLM applications using adversarial prompt generation, bias probes, and safety evaluations. Tests for prompt injection, jailbreaks, data extraction, and output quality degradation.',
    standards: ['OWASP LLM Top 10', 'NIST AI RMF', 'EU AI Act'],
  },

  // -- LLM Assurance (defending-code-reference-harness) --------------------
  'llm-threatmodel': {
    displayName: 'LLM Threat Model',
    category: 'LLM Assurance',
    description: 'LLM-generated, persistent per-project STRIDE threat model derived from the source tree',
    checksPerformed: [
      'System-context and asset enumeration',
      'Entry-point and trust-boundary mapping',
      'STRIDE threat enumeration',
      'Threat-class generalization from past vulnerabilities',
      'Impact/likelihood scoring of unmitigated threats',
      'Recommended class-level mitigations',
    ],
    scanScope: 'Full source tree under /scan-target (no build, no execution, no network)',
    methodology: 'Bounded agentic static analysis (Anthropic Messages API) ported from the defending-code-reference-harness threat-model bootstrap mode. Seeds the model with Code Hardener CA-001..010 analysis, then has Claude navigate the source via read/list/grep tools to produce a THREAT_MODEL.md (8-section contract). Persisted per project with staleness detection (inventory hash) so an unchanged tree reuses the model with zero API calls.',
    standards: ['OWASP Top 10', 'CWE Top 25'],
  },
  'llm-vuln-scan': {
    displayName: 'LLM Vulnerability Scan',
    category: 'LLM Assurance',
    description: 'Threat-model-scoped static vulnerability review using parallel bounded LLM agents',
    checksPerformed: [
      'Memory-safety review (overflow, use-after-free, integer overflow, format string)',
      'Injection & code-execution review (SQL/command/path/deserialization/XSS)',
      'Auth, crypto, and sensitive-data review',
      'Per-focus-area data-flow tracing (entry → sink → trigger)',
      'Per-finding confidence scoring (second-opinion pass)',
    ],
    scanScope: 'Source files within threat-model focus areas under /scan-target (static review only)',
    methodology: 'Faithful static port of the defending-code-reference-harness vuln-scan skill. Extracts focus areas from the persisted threat model (or a recon fallback), fans out one bounded Claude agent per focus area (concurrency 3) using the harness review brief and DO-NOT-REPORT false-positive exclusions, parses <finding> blocks, light-dedupes, then runs a Haiku confidence pass. Maps categories to CWE/OWASP. No build, execution, or network.',
    standards: ['OWASP Top 10', 'CWE Top 25'],
  },
};

/**
 * Get audit metadata for a scanner, with a sensible fallback for unknown scanners.
 */
export function getScannerAuditMeta(scanner: string): ScannerAuditMeta {
  return SCANNER_REGISTRY[scanner] || {
    displayName: scanner,
    category: 'Other',
    description: `Security analysis tool: ${scanner}`,
    checksPerformed: ['Security vulnerability detection'],
    scanScope: 'Source code and project files',
    methodology: 'Automated security analysis of project artifacts.',
    standards: ['OWASP Top 10'],
  };
}
