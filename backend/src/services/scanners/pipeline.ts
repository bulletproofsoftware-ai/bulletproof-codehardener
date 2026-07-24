import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import { env, llmVerifyEnabled } from '../../config/env.js';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, ScanEvidence } from '../../types/index.js';
import { getScannerAuditMeta } from './scanner-registry.js';

const execAsync = promisify(exec);

// ==========================================
// CATEGORY 1: SAST (Static Application Security Testing)
// ==========================================
import { runOpengrep } from './opengrep.js';      // 1. Semgrep/OpenGrep
import { runBandit } from './bandit.js';          // 2. Bandit (Python)
import { runGosec } from './gosec.js';            // 3. Gosec (Go)
import { runESLintSecurity } from './eslint-security.js'; // 4. ESLint Security (JS/TS)
import { runPMD } from './pmd.js';                // 5. PMD (Multi-language)

// ==========================================
// CATEGORY 2: DAST (Dynamic Application Security Testing)
// ==========================================
import { runNuclei } from './nuclei.js';          // 6. Nuclei
import { runZAP } from './zap.js';                // 7. OWASP ZAP

// ==========================================
// CATEGORY 3: SCA (Software Composition Analysis)
// ==========================================
import { runTrivy } from './trivy.js';            // 8. Trivy
import { runGrype } from './grype.js';            // 9. Grype

// ==========================================
// CATEGORY 4: Secrets Detection
// ==========================================
import { runGitleaks } from './gitleaks.js';      // 10. Gitleaks
// detect-secrets removed: redundant with Gitleaks (superset coverage)

// ==========================================
// CATEGORY 5: IaC Security
// ==========================================
import { runCheckov } from './checkov.js';        // 12. Checkov

// ==========================================
// CATEGORY 6: Load Testing
// ==========================================
import { runLocust } from './locust.js';          // 13. Locust
import { runArtillery } from './artillery.js';    // 14. Artillery
// k6 excluded: AGPL-3.0 license incompatible with platform distribution model (per PRD)

// ==========================================
// CATEGORY 7: API Testing
// ==========================================
import { runNewman } from './newman.js';          // 16. Newman
import { runPact } from './pact.js';              // 17. Pact
import { runRESTler } from './restler.js';        // 18. RESTler

// ==========================================
// CATEGORY 8: Browser/Visual Testing
// ==========================================
import { runPlaywright } from './playwright.js';  // 19. Playwright
import { runBackstop } from './backstop.js';      // 20. BackstopJS
import { runPa11y } from './pa11y.js';            // 21. Pa11y

// ==========================================
// CATEGORY 9: Supply Chain Security
// ==========================================
import { runSyft } from './syft.js';              // 22. Syft (SBOM)
// in-toto removed in v2: virtually no projects use .layout/.link files
import { runCosign } from './cosign.js';          // 24. Cosign

// ==========================================
// CATEGORY 10: Policy & Reporting
// ==========================================
import { runOPA } from './opa.js';                // 25. OPA
// allure removed in v2: passive report aggregator, requires pre-existing allure-results/
import { runConftest } from './conftest.js';      // 27. Conftest

// ==========================================
// CATEGORY 12: Additional SCA & Container Hardening
// ==========================================
import { runDockle } from './dockle.js';          // 31. Dockle (container hardening)
import { runHadolint } from './hadolint.js';      // 32. Hadolint (Dockerfile linting)

// ==========================================
// CATEGORY 13: Chaos & Runtime Testing
// ==========================================
// wiremock removed in v2: only validates mock config files, doesn't test actual APIs
// falco removed in v2: static Falco rule analysis too niche (<0.1% of repos use Falco)
import { runToxiproxy } from './toxiproxy.js';    // 34. Toxiproxy (chaos/resilience testing)
// flyway removed in v2: static SQL migration analysis, OpenGrep covers SQL injection patterns
// gatling removed in v2: passive results reader, Artillery + Locust cover load testing

// ==========================================
// CATEGORY 14: AI Code Quality
// ==========================================
import { runPackageValidator } from './package-validator.js';  // 37. Hallucinated package detection
import { runStryker } from './stryker.js';                    // 38. JS/TS mutation testing
import { runMutmut } from './mutmut.js';                      // 39. Python mutation testing
import { runPitest } from './pitest.js';                      // 40. Java mutation testing
import { runScancode } from './scancode.js';                  // 41. License snippet scanning
import { runSchemathesis } from './schemathesis.js';          // 42. Schema-driven API testing
import { runAFLpp } from './aflpp.js';                        // 43. Coverage-guided fuzzing
import { runKeploy } from './keploy.js';                      // 44. Record-replay API test coverage
import { runDeepEval } from './deepeval.js';                  // 45. LLM-as-Judge heuristic analysis
import { runJest } from './jest.js';                          // 47. Jest test runner (JS/TS)
import { runPytest } from './pytest.js';                      // 48. pytest test runner (Python)

// ==========================================
// CATEGORY 15: Threat Modeling
// ==========================================
import { runThreatModel } from './threatmodel.js';            // 46. STRIDE threat model analysis

// ==========================================
// CATEGORY 16: Code Quality & Dead Code
// ==========================================
import { runKnip } from './knip.js';                          // 49. Dead code detection (JS/TS)
import { runOxlint } from './oxlint.js';                      // 50. Fast JS/TS linter
import { runJscpd } from './jscpd.js';                        // 51. Cross-language copy-paste detection
import { runRuff } from './ruff.js';                          // 52. Python linting & formatting
import { runPhpstan } from './phpstan.js';                    // 53. PHP static analysis
import { runTypos } from './typos.js';                        // 54. Source code spell checking
import { runLibyear } from './libyear.js';                    // 55. Dependency freshness scoring

// ==========================================
// CATEGORY 17: CI/CD & Infrastructure Security
// ==========================================
import { runActionlint } from './actionlint.js';              // 56. GitHub Actions linting
import { runPoutine } from './poutine.js';                    // 57. CI/CD pipeline security
import { runScorecard } from './scorecard.js';                // 58. OpenSSF Scorecard
import { runKubeconform } from './kubeconform.js';            // 59. K8s manifest validation
import { runKubeLinter } from './kube-linter.js';             // 60. K8s security linting

// ==========================================
// CATEGORY 18: API & License Compliance
// ==========================================
import { runSpectral } from './spectral.js';                  // 61. OpenAPI spec linting
import { runDotenvLinter } from './dotenv-linter.js';         // 62. .env file validation
import { runCargoAudit } from './cargo-audit.js';             // 63. Rust SCA
import { runLicenseFinder } from './license-finder.js';       // 64. License compliance
import { runCdxgen } from './cdxgen.js';                      // 65. CycloneDX SBOM generation
import { runVale } from './vale.js';                          // 66. Documentation prose linting
import { runSeleniumGen } from './selenium-gen.js';            // 67. Selenium test generator

// ==========================================
// CATEGORY 19: New v2 Tools
// ==========================================
import { runLychee } from './lychee.js';                      // 68. Link checking
import { runAxeCore } from './axe-core.js';                   // 69. WCAG accessibility
import { runC8 } from './c8.js';                              // 70. Code coverage
import { runFastCheck } from './fast-check.js';               // 71. JS/TS property-based testing
import { runHypothesis } from './hypothesis.js';              // 72. Python property-based testing
import { runSqlmap } from './sqlmap.js';                      // 73. SQL injection testing
import { runDalfox } from './dalfox.js';                      // 74. XSS scanning
import { runFfuf } from './ffuf.js';                          // 75. Web fuzzing
import { runSocket } from './socket.js';                      // 76. Supply chain attack detection
import { runGiskard } from './giskard.js';                    // 77. LLM vulnerability testing

// ==========================================
// CATEGORY 20: LLM Assurance (defending-code-reference-harness)
// ==========================================
import { runLlmThreatmodel } from './llm-threatmodel.js';     // 78. LLM threat model
import { runLlmVulnScan } from './llm-vuln-scan.js';          // 79. LLM vulnerability scan
import { ScanTokenBudget } from './llm-agent.js';            // §11 R2 scan-scoped budget

import { detectLanguages } from './language-detector.js';
import { runCodeAnalysis, type FullAnalysisResult } from './code-analysis.js';
import { detectProjectContext } from './detect-context.js';
import { augmentScannersWithContext } from './smart-selection.js';
import { checkTargetHealth } from './target-health.js';

const logger = createLogger('scan-pipeline');

/** Result of the full scan pipeline including code analysis for enrichment */
export interface ScanPipelineResult {
  scannerResults: ScannerResult[];
  codeAnalysis: FullAnalysisResult | null;
  fileInventory: FileInventory;
  /**
   * Scan-scoped aggregate LLM token budget (spec §11 R2). Present only when
   * llmVerifyEnabled; shared by the in-pipeline LLM scanners AND the post-pipeline
   * triage/patch stages so total LLM cost across all four stages is bounded to a
   * single ceiling (not 4× the ceiling). Null when LLM scanning is disabled.
   */
  llmBudget: ScanTokenBudget | null;
}

// Scanner map for all active tools (removed detect-secrets, pip-audit, garak as redundant)
const SCANNER_MAP: Record<string, (data: ScanJobData) => Promise<ScannerResult>> = {
  // SAST
  opengrep: runOpengrep,
  semgrep: runOpengrep,  // Alias
  bandit: runBandit,
  gosec: runGosec,
  'eslint-security': runESLintSecurity,
  eslint: runESLintSecurity,  // Alias
  pmd: runPMD,

  // DAST
  nuclei: runNuclei,
  zap: runZAP,

  // SCA
  trivy: runTrivy,
  grype: runGrype,

  // Secrets
  gitleaks: runGitleaks,

  // IaC
  checkov: runCheckov,

  // Load Testing
  locust: runLocust,
  artillery: runArtillery,
  // k6 excluded (AGPL-3.0)

  // API Testing
  newman: runNewman,
  pact: runPact,
  restler: runRESTler,
  keploy: runKeploy,

  // Browser/Visual
  playwright: runPlaywright,
  backstop: runBackstop,
  pa11y: runPa11y,

  // Supply Chain
  syft: runSyft,
  cosign: runCosign,

  // Policy
  opa: runOPA,
  conftest: runConftest,

  // Container Hardening
  dockle: runDockle,
  hadolint: runHadolint,

  // Chaos/Resilience
  toxiproxy: runToxiproxy,

  // AI Code Quality
  'package-validator': runPackageValidator,
  stryker: runStryker,
  mutmut: runMutmut,
  pitest: runPitest,
  scancode: runScancode,
  schemathesis: runSchemathesis,
  aflpp: runAFLpp,
  deepeval: runDeepEval,
  jest: runJest,
  pytest: runPytest,

  // Threat Modeling
  threatmodel: runThreatModel,

  // Code Quality & Dead Code
  knip: runKnip,
  oxlint: runOxlint,
  jscpd: runJscpd,
  ruff: runRuff,
  phpstan: runPhpstan,
  typos: runTypos,
  vale: runVale,
  libyear: runLibyear,

  // CI/CD & Infrastructure Security
  actionlint: runActionlint,
  poutine: runPoutine,
  scorecard: runScorecard,
  kubeconform: runKubeconform,
  'kube-linter': runKubeLinter,

  // Additional SCA & Compliance
  'cargo-audit': runCargoAudit,
  spectral: runSpectral,
  'dotenv-linter': runDotenvLinter,
  'license-finder': runLicenseFinder,
  cdxgen: runCdxgen,

  // Test Generation
  'selenium-gen': runSeleniumGen,

  // New v2 Tools
  lychee: runLychee,
  'axe-core': runAxeCore,
  c8: runC8,
  'fast-check': runFastCheck,
  hypothesis: runHypothesis,
  sqlmap: runSqlmap,
  dalfox: runDalfox,
  ffuf: runFfuf,
  socket: runSocket,
  giskard: runGiskard,

  // LLM Assurance (defending-code-reference-harness)
  'llm-threatmodel': runLlmThreatmodel,
  'llm-vuln-scan': runLlmVulnScan,
};

// Scanner profiles optimized for different use cases
const PROFILE_SCANNERS: Record<string, string[]> = {
  // Fast scan for quick feedback (~30 seconds)
  quick: [
    'gitleaks',      // Secrets detection
    'trivy',         // Vulnerability scanning
  ],

  // Standard scan for regular development (~2-5 minutes)
  standard: [
    // Core security
    'trivy',
    'gitleaks',
    'opengrep',
    'checkov',
    // SCA
    'grype',
    'syft',
    // AI code quality (fast, non-blocking)
    'package-validator',
    // Code quality
    'oxlint',
    'ruff',
    'actionlint',
    'jscpd',
    'typos',
  ],

  // Comprehensive scan for releases/audits (~10-15 minutes)
  comprehensive: [
    // SAST (5)
    'opengrep',
    'bandit',
    'gosec',
    'eslint-security',
    'pmd',
    // DAST (2)
    'nuclei',
    'zap',
    // SCA (2)
    'trivy',
    'grype',
    // Secrets (1)
    'gitleaks',
    // IaC (1)
    'checkov',
    // API Testing (4)
    'newman',
    'restler',
    'schemathesis',
    'keploy',
    // Supply Chain (3)
    'syft',
    'cosign',
    'dockle',
    'hadolint',
    // Policy (2)
    'opa',
    'conftest',
    // AI Code Quality (6)
    'package-validator',
    'scancode',
    'stryker',
    'mutmut',
    'pitest',
    'deepeval',
    // Test Runners (2)
    'jest',
    'pytest',
    // Fuzz Testing (1)
    'aflpp',
    // Threat Modeling (1)
    'threatmodel',
    // Code Quality (7)
    'knip',
    'oxlint',
    'jscpd',
    'ruff',
    'phpstan',
    'typos',
    'libyear',
    // CI/CD Security (5)
    'actionlint',
    'poutine',
    'scorecard',
    'kubeconform',
    'kube-linter',
    // Additional SCA & Compliance (5)
    'cargo-audit',
    'spectral',
    'dotenv-linter',
    'license-finder',
    'cdxgen',
    // Test Generation (1)
    'selenium-gen',
    // New v2 Tools (10)
    'lychee',
    'axe-core',
    'c8',
    'fast-check',
    'hypothesis',
    'sqlmap',
    'dalfox',
    'ffuf',
    'socket',
    'giskard',
  ],

  // Security-focused scan
  security: [
    'opengrep',
    'bandit',
    'gosec',
    'eslint-security',
    'nuclei',
    'zap',
    'trivy',
    'grype',
    'gitleaks',
    'checkov',
    'syft',
    'dockle',
    'hadolint',
    'threatmodel',
    'actionlint',
    'poutine',
    'scorecard',
    'cargo-audit',
    'sqlmap',
    'dalfox',
    'ffuf',
    'socket',
  ],

  // API testing focused
  api: [
    'newman',
    'pact',
    'restler',
    'nuclei',
    'schemathesis',
    'keploy',
    'spectral',
  ],

  // Performance/load testing focused
  performance: [
    'locust',
    'artillery',
  ],

  // Frontend/accessibility focused
  frontend: [
    'playwright',
    'backstop',
    'pa11y',
    'axe-core',
    'eslint-security',
    'selenium-gen',
    'lychee',
  ],

  // Supply chain security focused
  'supply-chain': [
    'syft',
    'cosign',
    'trivy',
    'grype',
    'dockle',
    'hadolint',
    'package-validator',
    'scancode',
    'license-finder',
    'cdxgen',
    'cargo-audit',
    'socket',
  ],

  // AI/LLM security focused (code scanning + AI-specific risks)
  'ai-security': [
    'opengrep',
    'gitleaks',
    'package-validator',
    'scancode',
    'trivy',
    'eslint-security',
    'bandit',
    'giskard',
    'socket',
  ],

  // AI code quality — purpose-built for AI-generated codebases
  'ai-code-quality': [
    'package-validator',  // Hallucinated package detection
    'deepeval',          // LLM-as-Judge heuristic analysis
    'stryker',           // JS/TS mutation testing
    'mutmut',            // Python mutation testing
    'pitest',            // Java mutation testing
    'jest',              // JS/TS test runner
    'pytest',            // Python test runner
    'c8',                // Code coverage
    'fast-check',        // Property-based testing (JS/TS)
    'hypothesis',        // Property-based testing (Python)
    'scancode',          // License snippet scanning
    'schemathesis',      // API schema validation
    'keploy',            // API test coverage gaps
    'opengrep',          // SAST
    'trivy',             // SCA
    'gitleaks',          // Secrets
    'eslint-security',   // JS/TS SAST
    'bandit',            // Python SAST
    'knip',              // Dead code detection
    'oxlint',            // Fast JS/TS linting
    'ruff',              // Python linting
    'jscpd',             // Copy-paste detection
    'typos',             // Spell checking
    'libyear',           // Dependency freshness
    'giskard',           // LLM vulnerability testing
    'selenium-gen',      // Selenium test generation
  ],

  // Database/migration security
  database: [
    'opengrep',
    'gitleaks',
  ],

  // Chaos/resilience testing
  chaos: [
    'toxiproxy',
    'artillery',
    'locust',
  ],

  // PR-level incremental scan (fast, security-focused)
  pr: [
    'gitleaks',
    'trivy',
    'opengrep',
    'eslint-security',
    'bandit',
    'ruff',
    'oxlint',
  ],

  // Ultrafast pre-commit hook (~30s, changed files only)
  'pre-commit': [
    'gitleaks',
    'trivy',
    'opengrep',
    'oxlint',
    'ruff',
    'typos',
  ],

  // Compliance audit — maps findings to SOC2/ISO27001/NIST/PCI frameworks
  compliance: [
    'trivy', 'grype', 'gitleaks', 'checkov', 'syft', 'cdxgen',
    'license-finder', 'scancode', 'cosign', 'scorecard', 'opa', 'conftest',
    'dockle', 'hadolint', 'actionlint', 'poutine',
  ],

  // Usability & accessibility testing
  usability: [
    'pa11y', 'axe-core', 'backstop', 'playwright', 'selenium-gen', 'lychee', 'vale',
  ],

  // Unit/mutation testing focused
  'unit-test': [
    'jest', 'pytest', 'stryker', 'mutmut', 'pitest', 'c8', 'fast-check', 'hypothesis',
  ],

  // Full scan with all tools
  full: Object.keys(SCANNER_MAP).filter(s => !['semgrep', 'eslint'].includes(s)), // Exclude aliases
};

// Deep scan = comprehensive + the two LLM assurance scanners (§12). Defined after
// the literal so it can reference the comprehensive list. The LLM scanners are
// cost-gated by the per-project opt-in (spec §11 R3), so always-including them in
// full is intentional.
PROFILE_SCANNERS.deep = [
  ...PROFILE_SCANNERS.comprehensive,
  'llm-threatmodel',
  'llm-vuln-scan',
];

const SCAN_TARGET = '/scan-target';

// ==========================================
// FILE INVENTORY — Collect codebase metrics for audit evidence
// ==========================================

export interface FileInventory {
  totalFiles: number;
  sourceFiles: number;
  byExtension: Record<string, number>;
  byLanguage: Record<string, number>;
}

/** Extensions grouped by language for scanner→file count mapping */
const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  'JavaScript/TypeScript': ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'],
  'Python': ['py', 'pyi'],
  'Go': ['go'],
  'Java': ['java'],
  'Ruby': ['rb'],
  'PHP': ['php'],
  'Rust': ['rs'],
  'C/C++': ['c', 'cpp', 'cc', 'h', 'hpp'],
  'C#': ['cs'],
  'Swift': ['swift'],
  'Kotlin': ['kt', 'kts'],
  'Scala': ['scala'],
  'Shell': ['sh', 'bash', 'zsh'],
  'IaC': ['tf', 'hcl', 'bicep'],
  'Config': ['json', 'yaml', 'yml', 'toml', 'xml', 'ini', 'env'],
  'Docker': ['dockerfile'],
  'Markdown': ['md', 'rst', 'txt', 'adoc'],
};

/** Maps scanner names to the language groups they analyze. Empty = all files. */
const SCANNER_FILE_SCOPE: Record<string, string[]> = {
  'opengrep': ['JavaScript/TypeScript', 'Python', 'Go', 'Java', 'Ruby', 'PHP', 'Rust', 'C/C++', 'C#', 'Kotlin', 'Scala', 'Shell'],
  'bandit': ['Python'],
  'gosec': ['Go'],
  'eslint-security': ['JavaScript/TypeScript'],
  'pmd': ['Java', 'JavaScript/TypeScript'],
  'stryker': ['JavaScript/TypeScript'],
  'mutmut': ['Python'],
  'pitest': ['Java'],
  'jest': ['JavaScript/TypeScript'],
  'pytest': ['Python'],
  'deepeval': ['JavaScript/TypeScript', 'Python', 'Go', 'Java', 'Ruby'],
  'checkov': ['IaC', 'Docker', 'Config'],
  'conftest': ['IaC', 'Config'],
  // Code Quality & Dead Code
  'knip': ['JavaScript/TypeScript'],
  'oxlint': ['JavaScript/TypeScript'],
  'ruff': ['Python'],
  'phpstan': ['PHP'],
  'vale': ['Markdown'],
  'spectral': ['Config'],
  'jscpd': ['JavaScript/TypeScript', 'Python', 'Go', 'Java', 'Ruby', 'PHP', 'Rust', 'C/C++'],
  // CI/CD (analyze workflow/config files, not source)
  'actionlint': ['Config'],
  'kubeconform': ['Config'],
  'kube-linter': ['Config'],
  'dotenv-linter': ['Config'],
  // Rust SCA
  'cargo-audit': ['Rust'],
  // Test Generation
  'selenium-gen': ['JavaScript/TypeScript', 'Python', 'Go', 'Java', 'Ruby', 'PHP'],
  // New v2 tools
  'lychee': ['Markdown'],
  'c8': ['JavaScript/TypeScript'],
  'fast-check': ['JavaScript/TypeScript'],
  'hypothesis': ['Python'],
  'giskard': ['JavaScript/TypeScript', 'Python'],
  // DAST scanners (axe-core, sqlmap, dalfox, ffuf, socket) → empty array = all files
  // LLM Assurance scanners review any language → empty array = all files
  'llm-threatmodel': [],
  'llm-vuln-scan': [],
};

/**
 * Count and categorize all files in /scan-target for audit evidence.
 * This runs ONCE before scanners and provides the "total files analyzed" number.
 */
async function collectFileInventory(): Promise<FileInventory> {
  try {
    const { stdout } = await execAsync(
      `find ${SCAN_TARGET} -type f ` +
        `-not -path '*/.git/*' ` +
        `-not -path '*/node_modules/*' ` +
        `-not -path '*/.venv/*' ` +
        `-not -path '*/venv/*' ` +
        `-not -path '*/__pycache__/*' ` +
        `-not -path '*/.next/*' ` +
        `-not -path '*/dist/*' ` +
        `-not -path '*/build/*' ` +
        `-not -path '*/.cache/*' ` +
        `-not -path '*/.tox/*' ` +
        `-not -path '*/vendor/*' ` +
        `2>/dev/null | head -50000`,
      { maxBuffer: 20 * 1024 * 1024, timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);
    const byExtension: Record<string, number> = {};

    for (const file of files) {
      // Handle Dockerfile specially (no extension)
      const basename = file.split('/').pop() || '';
      let ext: string;
      if (basename.toLowerCase() === 'dockerfile' || basename.toLowerCase().startsWith('dockerfile.')) {
        ext = 'dockerfile';
      } else {
        ext = basename.includes('.') ? (basename.split('.').pop()?.toLowerCase() || 'other') : 'other';
      }
      byExtension[ext] = (byExtension[ext] || 0) + 1;
    }

    // Build language breakdown from extension counts
    const byLanguage: Record<string, number> = {};
    for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
      const count = exts.reduce((sum, ext) => sum + (byExtension[ext] || 0), 0);
      if (count > 0) byLanguage[lang] = count;
    }

    const sourceExts = new Set(
      Object.entries(LANGUAGE_EXTENSIONS)
        .filter(([lang]) => !['Config', 'Markdown', 'Docker'].includes(lang))
        .flatMap(([, exts]) => exts)
    );
    const sourceFiles = Object.entries(byExtension)
      .filter(([ext]) => sourceExts.has(ext))
      .reduce((sum, [, count]) => sum + count, 0);

    logger.info({ totalFiles: files.length, sourceFiles, languages: Object.keys(byLanguage) }, 'File inventory collected');

    return { totalFiles: files.length, sourceFiles, byExtension, byLanguage };
  } catch (error) {
    logger.warn({ error }, 'File inventory collection failed — continuing without it');
    return { totalFiles: 0, sourceFiles: 0, byExtension: {}, byLanguage: {} };
  }
}

/**
 * Set filesAnalyzed on scanner results that didn't report their own count.
 * Uses the file inventory to infer how many files the scanner would have analyzed
 * based on the scanner's language scope.
 */
function applyFileInventoryCounts(results: ScannerResult[], inventory: FileInventory): ScannerResult[] {
  return results.map(result => {
    // Skip if scanner already reported a meaningful file count
    if (result.evidence?.filesAnalyzed && result.evidence.filesAnalyzed > 0) {
      return result;
    }

    const languages = SCANNER_FILE_SCOPE[result.scanner];
    let count: number;

    if (!languages || languages.length === 0) {
      // Scanner operates on all files (secrets detection, SCA, SBOM, etc.)
      count = inventory.totalFiles;
    } else {
      // Scanner targets specific languages — sum their file counts
      count = languages.reduce((sum, lang) => sum + (inventory.byLanguage[lang] || 0), 0);
      if (count === 0) count = inventory.sourceFiles; // Fallback: all source files
    }

    return {
      ...result,
      evidence: {
        ...result.evidence,
        filesAnalyzed: count,
      },
    };
  });
}

/**
 * Prepare the scan target directory with fresh code from the repository.
 * Clones if empty, pulls if already a git repo for the same URL, or re-clones if URL changed.
 */
async function prepareScanTarget(jobData: ScanJobData): Promise<void> {
  let repoUrl = jobData.repositoryUrl;

  // If no URL in job data, look it up from the project
  if (!repoUrl) {
    const project = await db.execute(sql`
      SELECT repo_url FROM projects WHERE id = ${jobData.projectId}
    `);
    repoUrl = (project.rows[0] as any)?.repo_url || '';
  }

  if (!repoUrl) {
    logger.warn({ scanId: jobData.scanId }, 'No repository URL — scanning existing /scan-target contents');
    return;
  }

  const branch = jobData.branch || 'main';

  try {
    // Check if /scan-target is already a git repo with the same remote
    const { stdout: remoteUrl } = await execAsync(
      `cd ${SCAN_TARGET} && git remote get-url origin 2>/dev/null || echo ""`,
      { timeout: 10000 }
    );

    if (remoteUrl.trim() === repoUrl) {
      // Same repo — fetch and checkout the right branch
      logger.info({ scanId: jobData.scanId, branch }, 'Updating existing scan target');
      await execAsync(
        `cd ${SCAN_TARGET} && git fetch origin && git checkout -f ${branch} && git reset --hard origin/${branch}`,
        { timeout: 60000 }
      );
    } else {
      // Different repo or not a git repo — clean and clone
      logger.info({ scanId: jobData.scanId, repoUrl, branch }, 'Cloning repository into scan target');
      await execAsync(
        `rm -rf ${SCAN_TARGET}/* ${SCAN_TARGET}/.[!.]* 2>/dev/null; git clone --depth 1 --branch ${branch} ${repoUrl} ${SCAN_TARGET}`,
        { timeout: 120000 }
      );
    }

    // If a specific commit was requested, check it out
    if (jobData.commitSha) {
      // Need full history for specific commit checkout — unshallow first
      await execAsync(
        `cd ${SCAN_TARGET} && git fetch --unshallow 2>/dev/null; git checkout ${jobData.commitSha}`,
        { timeout: 120000 }
      );
    }

    logger.info({ scanId: jobData.scanId, repoUrl, branch }, 'Scan target prepared');
  } catch (error) {
    logger.error({ error, scanId: jobData.scanId, repoUrl }, 'Failed to prepare scan target — scanning stale contents');
  }
}

/**
 * Enrich a scanner result with audit evidence from the registry if the scanner
 * didn't provide its own evidence. Ensures every scanner result has evidence
 * for regulatory audit compliance.
 */
function enrichWithEvidence(result: ScannerResult): ScannerResult {
  const meta = getScannerAuditMeta(result.scanner);

  // If scanner already provided evidence, merge with registry defaults
  const evidence: ScanEvidence = {
    checksPerformed: meta.checksPerformed,
    scanScope: meta.scanScope,
    ...result.evidence, // Scanner-provided values override defaults
  };

  return { ...result, evidence };
}

export async function runScanPipeline(jobData: ScanJobData): Promise<ScanPipelineResult> {
  const { scanId, profile, scanners: requestedScanners } = jobData;

  // Refresh /scan-target with latest code before scanning
  await prepareScanTarget(jobData);

  // For incremental (PR) scans, log changed files for filtering
  if (jobData.scope === 'incremental' && jobData.prContext?.changedFiles?.length) {
    logger.info({ scanId, changedFiles: jobData.prContext.changedFiles.length }, 'Incremental scan — filtering to changed files');
  }

  // Collect file inventory BEFORE running scanners (audit evidence of what was analyzed)
  const fileInventory = await collectFileInventory();

  // Run code analysis for finding enrichment (non-blocking — null on failure)
  const codeAnalysis = await runCodeAnalysis(SCAN_TARGET);
  // Thread onto jobData so LLM scanners reuse it instead of re-running CA (§12)
  jobData.codeAnalysis = codeAnalysis;

  // Auto-detect project context (API specs, Docker files, etc.)
  const detectedSpecs = await detectProjectContext(SCAN_TARGET);
  jobData.detectedSpecs = detectedSpecs;

  // Health check targetUrl before running DAST scanners
  let targetReachable = false;
  if (jobData.targetUrl) {
    const timeout = (jobData.options?.healthCheckTimeout as number | undefined) ?? 5000;
    targetReachable = await checkTargetHealth(jobData.targetUrl, timeout);
    if (!targetReachable) {
      logger.warn({ targetUrl: jobData.targetUrl, scanId }, 'Target URL unreachable — DAST scanners will be skipped');
    }
  }

  // Determine which scanners to run
  let scannersToRun: string[];

  if (requestedScanners && requestedScanners.length > 0) {
    // Use explicitly requested scanners
    scannersToRun = requestedScanners.filter(s => SCANNER_MAP[s]);
  } else if (profile === 'auto') {
    // Auto-detect languages and select appropriate scanners
    const detection = await detectLanguages();
    if (detection.recommendedScanners.length > 0) {
      scannersToRun = detection.recommendedScanners.filter(s => SCANNER_MAP[s]);
      logger.info(
        { scanId, languages: detection.languages, recommended: scannersToRun.length },
        'Auto-detected languages, selected scanners'
      );
    } else {
      // Fallback to standard if detection fails
      scannersToRun = PROFILE_SCANNERS.standard;
      logger.warn({ scanId }, 'Language detection found nothing, falling back to standard profile');
    }
  } else {
    // Use profile-based selection
    scannersToRun = PROFILE_SCANNERS[profile] || PROFILE_SCANNERS.standard;
  }

  // Context-aware augmentation: add scanners based on detected context
  scannersToRun = augmentScannersWithContext(scannersToRun, profile, {
    targetUrl: jobData.targetUrl,
    containerImage: jobData.containerImage,
    detectedSpecs: jobData.detectedSpecs,
  });

  // §11 R2: construct ONE scan-scoped LLM token budget and thread it onto jobData
  // so every LLM scanner (threatmodel, vuln-scan) shares a single aggregate ceiling
  // instead of each minting its own (which would allow up to 4× the configured cap).
  // Only meaningful when LLM scanning is enabled; returned for the post-pipeline
  // triage/patch stages to consume the same budget.
  const llmBudget = llmVerifyEnabled ? new ScanTokenBudget(env.LLM_SCAN_MAX_TOTAL_TOKENS) : null;
  jobData.llmBudget = llmBudget ?? undefined;

  logger.info({ scanId, profile, scanners: scannersToRun, count: scannersToRun.length }, 'Starting scan pipeline');

  const results: ScannerResult[] = [];
  const timeout = env.SCANNER_TIMEOUT_MS;
  const maxConcurrent = env.SCANNER_MAX_CONCURRENT;

  // Run a single scanner with the standard timeout race + evidence/error handling.
  // Shared by the threat-model pre-pass and the chunked concurrency loop so every
  // scanner's result is recorded through one identical path.
  const runOneScanner = async (scanner: string): Promise<ScannerResult | null> => {
    const runScanner = SCANNER_MAP[scanner];
    if (!runScanner) {
      logger.warn({ scanner }, 'Unknown scanner');
      return null;
    }
    // F3: give each scanner its own abort controller. The LLM scanners thread
    // jobData.llmAbortSignal into their bounded-agent loops; when the timeout
    // race below wins we abort it so those loops stop issuing API calls instead
    // of running orphaned and draining the shared scan-scoped budget. Cleared in
    // `finally` so the signal never leaks to the next scanner in the chunk.
    const llmAbort = new AbortController();
    jobData.llmAbortSignal = llmAbort.signal;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    try {
      const startTime = Date.now();
      const result = await Promise.race([
        runScanner(jobData),
        new Promise<ScannerResult>((_, reject) => {
          timeoutHandle = setTimeout(() => {
            llmAbort.abort();
            reject(new Error('Scanner timeout'));
          }, timeout);
        }),
      ]);
      logger.info(
        { scanner, duration: Date.now() - startTime, findingsCount: result.findings.length },
        'Scanner completed'
      );
      return enrichWithEvidence(result);
    } catch (error) {
      logger.error({ error, scanner }, 'Scanner failed');
      return {
        scanner,
        success: false,
        findings: [],
        duration: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    } finally {
      // F3: clear the timeout (if the scanner finished first) and detach the
      // signal so it never leaks into the next scanner sharing jobData.
      if (timeoutHandle) clearTimeout(timeoutHandle);
      jobData.llmAbortSignal = undefined;
    }
  };

  // ADV-1 dependency ordering: llm-vuln-scan reads the CURRENT scan's threat model
  // for its focus areas, so llm-threatmodel MUST complete first. Pull it out of the
  // concurrency-chunked list and run it to completion as a pre-pass BEFORE the loop,
  // rather than relying on chunk boundaries happening to schedule it first.
  if (scannersToRun.includes('llm-threatmodel')) {
    scannersToRun = scannersToRun.filter((s) => s !== 'llm-threatmodel');
    const tmResult = await runOneScanner('llm-threatmodel');
    if (tmResult !== null) results.push(tmResult);
  }

  // Run remaining scanners with concurrency limit
  const chunks = [];
  for (let i = 0; i < scannersToRun.length; i += maxConcurrent) {
    chunks.push(scannersToRun.slice(i, i + maxConcurrent));
  }

  for (const chunk of chunks) {
    const chunkResults = await Promise.all(chunk.map((scanner) => runOneScanner(scanner)));
    results.push(...chunkResults.filter((r): r is ScannerResult => r !== null));
  }

  // Apply file inventory counts to scanners that didn't report their own
  const enrichedResults = applyFileInventoryCounts(results, fileInventory);

  const totalFindings = enrichedResults.reduce((acc, r) => acc + r.findings.length, 0);
  const successfulScanners = enrichedResults.filter(r => r.success).length;

  logger.info(
    {
      scanId,
      scannersRun: enrichedResults.length,
      successfulScanners,
      failedScanners: enrichedResults.length - successfulScanners,
      totalFindings,
      fileInventory: { total: fileInventory.totalFiles, source: fileInventory.sourceFiles },
    },
    'Scan pipeline completed'
  );

  // Add file inventory as a pseudo-scanner entry so it gets stored in scanners_executed JSONB
  enrichedResults.push({
    scanner: '_file_inventory',
    success: true,
    findings: [],
    duration: 0,
    evidence: {
      filesAnalyzed: fileInventory.totalFiles,
      scanScope: `${fileInventory.totalFiles} total files (${fileInventory.sourceFiles} source code)`,
      checksPerformed: Object.entries(fileInventory.byLanguage)
        .sort(([, a], [, b]) => b - a)
        .map(([lang, count]) => `${lang}: ${count} files`),
      targetsAnalyzed: Object.entries(fileInventory.byExtension)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 30)
        .map(([ext, count]) => `.${ext}: ${count}`),
    },
  });

  return { scannerResults: enrichedResults, codeAnalysis, fileInventory, llmBudget };
}

// Export for use in other modules
export { SCANNER_MAP, PROFILE_SCANNERS };
