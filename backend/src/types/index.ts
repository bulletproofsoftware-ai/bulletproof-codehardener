// Common types used across the application

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type FindingStatus = 'open' | 'fixed' | 'ignored' | 'false_positive' | 'deferred';

export type Exploitability = 'confirmed' | 'likely' | 'theoretical' | 'unlikely';
export type DataflowMatchType = 'confirmed' | 'sanitized' | 'no_match';

export type QualityLevel = 'excellent' | 'good' | 'moderate' | 'poor' | 'critical' | 'unknown';

export interface PaginationParams {
  page: number;
  limit: number;
}

export interface PaginatedResult<T> {
  data: T[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface User {
  id: string;
  email: string;
  name: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface Project {
  id: string;
  userId: string;
  name: string;
  description: string | null;
  repositoryUrl: string | null;
  defaultBranch: string;
  lastScanId: string | null;
  lastScanAt: Date | null;
  lastScore: number | null;
  targetUrl: string | null;
  containerImage: string | null;
  openapiSpecPath: string | null;
  authConfigured: boolean;
  registryCredentialsId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface Scan {
  id: string;
  projectId: string;
  userId: string;
  status: ScanStatus;
  profile: string;
  branch: string | null;
  commitSha: string | null;
  score: number | null;
  qualityLevel: QualityLevel | null;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  scannersRun: string[];
  duration: number | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface Finding {
  id: string;
  scanId: string;
  projectId: string;
  scanner: string;
  ruleId: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  titleSimple: string | null;
  description: string;
  descriptionSimple: string | null;
  filePath: string | null;
  lineNumber: number | null;
  columnNumber: number | null;
  codeSnippet: string | null;
  cweId: string | null;
  owaspCategory: string | null;
  fixAvailable: boolean;
  fixDescription: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface Attestation {
  id: string;
  scanId: string;
  attestationType: string;
  subjectName: string | null;
  subjectDigest: string | null;
  predicate: Record<string, unknown> | null;
  predicateType: string | null;
  signature: string | null;
  signatureAlgorithm: string | null;
  certificate: string | null;
  certificateChain: string | null;
  rekorLogId: string | null;
  rekorLogIndex: number | null;
  transparencyLogUrl: string | null;
  attestationJson: Record<string, unknown> | null;
  createdAt: Date;
}

export interface Policy {
  id: string;
  userId: string;
  name: string;
  description: string | null;
  isDefault: boolean;
  rules: PolicyRule[];
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyRule {
  severity: Severity;
  action: 'block' | 'warn' | 'ignore';
  maxAllowed: number | null;
  categories?: string[];
  scanners?: string[];
}

export interface ApiKey {
  id: string;
  userId: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  scopes: string[];
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
}

export interface Webhook {
  id: string;
  userId: string;
  url: string;
  secret: string;
  events: string[];
  isActive: boolean;
  lastTriggeredAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

// Scanner types

/** Structured audit evidence returned by each scanner for regulatory compliance */
export interface ScanEvidence {
  /** Number of files analyzed by this scanner */
  filesAnalyzed?: number;
  /** Number of rules, patterns, or checks evaluated */
  rulesEvaluated?: number;
  /** List of specific check categories performed */
  checksPerformed?: string[];
  /** Description of what was scanned (scope) */
  scanScope?: string;
  /** Tool version used for this scan */
  toolVersion?: string;
  /** Detection method used (e.g., 'library' vs 'regex-fallback') */
  detectionMethod?: string;
  /** Configuration or ruleset applied */
  configuration?: string;
  /** Targets analyzed (e.g., packages, images, endpoints) */
  targetsAnalyzed?: string[];
  /** SBOM package list (populated by Syft scanner) */
  sbomPackages?: Array<{ name: string; version: string; type: string; language: string; license: string }>;
  /** Whether DAST scanner ran with authentication context */
  authenticationStatus?: 'authenticated' | 'unauthenticated' | 'auth-available-not-supported';
}

export interface ScannerResult {
  scanner: string;
  success: boolean;
  findings: NormalizedFinding[];
  duration: number;
  error?: string;
  rawOutput?: string;
  /** True when scanner had nothing to scan (no config, no target, no matching files) */
  skipped?: boolean;
  /** Machine-readable reason for skipping */
  skipReason?: 'no_target_url' | 'no_container_image' | 'no_api_spec' |
               'no_matching_files' | 'no_test_config' | 'coverage_threshold' |
               'no_postman_collection' | 'no_pact_contracts' | 'binary_not_found' |
               'target_unreachable' | 'no_python_project' | 'no_java_project' |
               'no_c_project' | 'no_rust_project' | 'no_ci_config' |
               'no_k8s_manifests' | 'no_policy_dir' | 'tool_not_installed' |
               'no_git_repo' | 'no_web_endpoints' | 'no_llm_integration' |
               'no_property_tests' | 'no_package_manifest' | 'no_mock_files' |
               'no_config_files' | 'no_llm_api_key' | 'llm_not_opted_in' |
               'llm_budget_exhausted' | 'llm_threatmodel_incomplete';
  /** Human-readable hint for resolving the skip (shown in dashboard) */
  skipHint?: string;
  /** Structured audit evidence for compliance reporting */
  evidence?: ScanEvidence;
}

/** Auto-detected project context from file globs (populated by detectProjectContext) */
export interface DetectedProjectContext {
  openapi: string[];
  postmanCollections: string[];
  pactContracts: string[];
  dockerComposeFile: string | null;
  dockerfile: string | null;
  /** Detected framework (e.g., 'express', 'django', 'spring-boot') — for future target URL suggestions */
  detectedFramework: string | null;
  /** Suggested dev server port parsed from Procfile/package.json scripts — informational only */
  suggestedDevPort: number | null;
}

export interface NormalizedFinding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  filePath: string | null;
  lineNumber: number | null;
  columnNumber: number | null;
  codeSnippet: string | null;
  cweId: string | null;
  owaspCategory: string | null;
  fixAvailable: boolean;
  fixDescription: string | null;
  metadata: Record<string, unknown>;
}

// Dashboard summary
export interface DashboardSummary {
  qualityScore: number;
  scoreTrend: 'up' | 'down' | 'stable';
  projectCount: number;
  openFindings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scansThisMonth: number;
  scanLimit: number | null;
  recentScans: Scan[];
  recentProjects: Project[];
  criticalFindings: Finding[];
}

// ============================================================================
// LLM Assurance Scanners (defending-code-reference-harness integration)
// Row shapes for migration 020 tables. DB access is raw parameterized `sql`
// (no Drizzle pgTable layer); these interfaces describe the result rows.
// ============================================================================

/** A single threat parsed from THREAT_MODEL.md section 4 (harness schema.md contract). */
export interface ParsedThreat {
  id: string;
  title: string;
  actor: string;
  surface: string;
  /** Section-2 asset(s) this threat compromises. */
  asset: string;
  impact: 'low' | 'medium' | 'high' | 'critical' | 'existential';
  likelihood: 'very_rare' | 'rare' | 'possible' | 'likely' | 'almost_certain';
  status: 'unmitigated' | 'partially_mitigated' | 'mitigated' | 'risk_accepted';
  /** Current mitigations, or "none". */
  controls: string;
  /** CVE/issue/commit ids instantiating this threat; may be empty. */
  evidence: string;
}

/** Row shape for the threat_models table. */
export interface ThreatModelRow {
  id: string;
  projectId: string;
  /** THREAT_MODEL.md markdown (harness schema.md contract) */
  content: string;
  /** Parsed section 4 threats (stored as a JSON string in threats_json) */
  threats: ParsedThreat[];
  /** Staleness-detection hash of the file inventory */
  sourceInventoryHash: string;
  modelUsed: string;
  generatedAt: Date;
  updatedAt: Date;
}

/** Row shape for the candidate_patches table. */
export interface CandidatePatchRow {
  id: string;
  findingId: string;
  scanId: string;
  /** Unified diff (rendered only inside fenced ```diff blocks) */
  patchDiff: string;
  rationale: string;
  /** LLM self-assessment (build / exploit-path-closed / tests / bypass) — unverified */
  validationNotes: string;
  modelUsed: string;
  status: 'proposed' | 'accepted' | 'rejected';
  createdAt: Date;
}
