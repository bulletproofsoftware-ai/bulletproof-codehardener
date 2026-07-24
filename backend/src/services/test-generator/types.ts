/**
 * Test Case Generator - Type Definitions
 * Covers CA-001 to CA-010, BP-001 to BP-003, TG-001 to TG-003
 */

// =============================================================================
// Code Analysis Types (CA-001 to CA-010)
// =============================================================================

/**
 * CA-001: Language Detection Result
 */
export interface LanguageDetection {
  language: string;
  percentage: number;
  fileCount: number;
  linesOfCode: number;
  extensions: string[];
}

/**
 * CA-002: Framework Detection Result
 */
export interface FrameworkDetection {
  framework: string;
  name?: string; // alias for framework (used by some modules)
  type: 'web' | 'api' | 'cli' | 'library' | 'mobile' | 'other';
  confidence: number;
  version?: string;
  indicators: string[];
  configFile?: string;
}

/**
 * CA-003: Extracted Endpoint
 */
export interface ExtractedEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD' | 'ALL';
  path: string;
  file: string;
  line: number;
  column?: number;
  handler?: string;
  middleware?: string[];
  parameters?: EndpointParameter[];
  authentication?: string;
  auth?: string; // alias for authentication (used by some modules)
  description?: string;
  isGraphQL?: boolean;
  graphqlType?: 'query' | 'mutation' | 'subscription';
}

export interface EndpointParameter {
  name: string;
  location: 'path' | 'query' | 'body' | 'header' | 'cookie';
  type?: string;
  required?: boolean;
  validation?: string;
}

/**
 * CA-004: Authentication Pattern
 */
export interface AuthPattern {
  type: 'jwt' | 'session' | 'oauth' | 'api_key' | 'basic' | 'bearer' | 'custom' | 'none';
  file: string;
  line: number;
  mechanism: string;
  library?: string;
  securityConcerns?: string[];
  indicators: string[];
}

/**
 * CA-005: Data Flow
 */
export interface DataFlow {
  id: string;
  source: DataFlowSource;
  sink: DataFlowSink;
  path: DataFlowStep[];
  sanitized: boolean;
  validated: boolean;
  tainted: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export interface DataFlowSource {
  type: 'user_input' | 'file' | 'env' | 'db' | 'api' | 'config';
  location: string;
  variable: string;
  line: number;
}

export interface DataFlowSink {
  type: 'db' | 'file' | 'response' | 'log' | 'external_api' | 'command' | 'eval';
  location: string;
  operation: string;
  line: number;
}

export interface DataFlowStep {
  file: string;
  line: number;
  operation: string;
  variable?: string;
}

/**
 * CA-006: Sensitive Data Point
 */
export interface SensitiveDataPoint {
  type: 'pii' | 'credential' | 'financial' | 'health' | 'location' | 'custom';
  field: string;
  file: string;
  line: number;
  encrypted: boolean;
  masked: boolean;
  classification: string;
  context?: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * CA-007: Dependency
 */
export interface Dependency {
  name: string;
  version: string;
  manifest: string;
  type: 'direct' | 'transitive' | 'dev';
  ecosystem: 'npm' | 'pip' | 'go' | 'maven' | 'gem' | 'cargo' | 'composer' | 'nuget';
  hasKnownVulnerabilities?: boolean;
  vulnerabilities?: VulnerabilityInfo[];
}

export interface VulnerabilityInfo {
  cveId?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  fixedVersion?: string;
  description?: string;
}

/**
 * CA-008: Infrastructure File
 */
export interface InfrastructureFile {
  type: 'dockerfile' | 'docker-compose' | 'kubernetes' | 'terraform' | 'cloudformation' | 'ansible' | 'helm' | 'github-actions' | 'gitlab-ci' | 'jenkinsfile';
  path: string;
  securityConcerns?: string[];
  services?: string[];
  ports?: number[];
  volumes?: string[];
}

/**
 * CA-009: Code Summary
 */
export interface CodeSummary {
  totalFiles: number;
  totalLinesOfCode: number;
  languages: LanguageDetection[];
  frameworks: FrameworkDetection[];
  entryPoints: string[];
  securityConcerns: SecurityConcern[];
  complexity: 'simple' | 'moderate' | 'complex';
  testCoverage?: number;
  lastCommit?: {
    hash: string;
    date: Date;
    message: string;
  };
}

export interface SecurityConcern {
  concern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location?: string;
  recommendation?: string;
}

/**
 * Complete Code Analysis Result
 */
export interface CodeAnalysisResult {
  id: string;
  projectId: string;
  repositoryUrl?: string;
  analysisDate: Date;
  languages: LanguageDetection[];
  frameworks: FrameworkDetection[];
  endpoints: ExtractedEndpoint[];
  authPatterns: AuthPattern[];
  dataFlows: DataFlow[];
  sensitiveData: SensitiveDataPoint[];
  dependencies: Dependency[];
  infrastructure: InfrastructureFile[];
  summary: CodeSummary;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  error?: string;
  processingTimeMs?: number;
  // Derived properties used by generator modules
  hasDatabase?: boolean;
  hasAuthentication?: boolean;
  hasFileOperations?: boolean;
  hasUserInput?: boolean;
  hasShellCommands?: boolean;
}

// =============================================================================
// BRD Parsing Types (BP-001 to BP-003)
// =============================================================================

/**
 * Requirement type including 'non-functional' for backward compatibility
 */
export type RequirementType =
  | 'functional'
  | 'security'
  | 'performance'
  | 'compliance'
  | 'usability'
  | 'api'
  | 'other'
  | 'non-functional';

/**
 * BP-001/002/003: BRD Section
 */
export interface BRDSection {
  id: string;
  title: string;
  level: number;
  content: string;
  type?: RequirementType; // Section type (security, api, functional, etc.)
  subsections?: BRDSection[];
  requirements?: ParsedRequirement[];
  pageNumber?: number;
  lineStart?: number;
  lineEnd?: number;
}

/**
 * Source location for a requirement
 */
export interface RequirementSource {
  file: string;
  section: string;
  lineNumber?: number;
}

/**
 * BP-001/002/003: Parsed Requirement (extended version used by parsers)
 */
export interface ParsedRequirement {
  id: string;
  title: string;
  description: string;
  type: RequirementType;
  priority: 'critical' | 'high' | 'medium' | 'low';
  section?: string;
  pageNumber?: number;
  keywords?: string[];
  acceptanceCriteria?: string[];
  relatedRequirements?: string[];
  dependencies?: string[];
  userStory?: {
    role?: string;
    feature?: string;
    benefit?: string;
  };
  source?: string | RequirementSource;
  confidence?: number;
}

/**
 * BP-001/002/003: BRD Requirement (simplified version)
 */
export interface BRDRequirement {
  id: string;
  text: string;
  type: RequirementType;
  priority: 'critical' | 'high' | 'medium' | 'low';
  section?: string;
  pageNumber?: number;
  keywords?: string[];
  acceptanceCriteria?: string[];
  relatedRequirements?: string[];
}

/**
 * BRD Analysis Result
 */
export interface BRDAnalysisResult {
  id: string;
  projectId: string;
  documentName: string;
  documentType: 'markdown' | 'docx' | 'pdf' | 'text';
  analysisDate: Date;
  requirements: BRDRequirement[] | ParsedRequirement[];
  securityRequirements: BRDRequirement[] | ParsedRequirement[];
  functionalRequirements: BRDRequirement[] | ParsedRequirement[];
  performanceRequirements?: BRDRequirement[] | ParsedRequirement[];
  apiRequirements?: BRDRequirement[] | ParsedRequirement[];
  sections?: BRDSection[];
  status: 'pending' | 'processing' | 'completed' | 'failed';
  error?: string;
  metadata?: {
    totalPages?: number;
    totalWords?: number;
    sections?: string[];
  };
}

/**
 * Test Generation Result
 */
export interface TestGenerationResult {
  testCases: GeneratedTestCase[];
  coverage: {
    owasp: Record<string, number>;
    cwe: Record<string, number>;
    overall: number;
  };
  sourceFile?: string;
}

// =============================================================================
// Test Generation Types (TG-001 to TG-003)
// =============================================================================

/**
 * OWASP Top 10 (2021) Categories
 */
export type OWASPCategory =
  | 'A01:2021' // Broken Access Control
  | 'A02:2021' // Cryptographic Failures
  | 'A03:2021' // Injection
  | 'A04:2021' // Insecure Design
  | 'A05:2021' // Security Misconfiguration
  | 'A06:2021' // Vulnerable and Outdated Components
  | 'A07:2021' // Identification and Authentication Failures
  | 'A08:2021' // Software and Data Integrity Failures
  | 'A09:2021' // Security Logging and Monitoring Failures
  | 'A10:2021'; // Server-Side Request Forgery (SSRF)

/**
 * OWASP Category Information
 */
export interface OWASPCategoryInfo {
  id: OWASPCategory;
  name: string;
  description: string;
  primaryScanners: string[];
  relatedCWEs: number[];
}

/**
 * CWE Top 25 Categories (2023)
 */
export const CWE_TOP_25 = [
  787, // Out-of-bounds Write
  79,  // Cross-site Scripting (XSS)
  89,  // SQL Injection
  416, // Use After Free
  78,  // OS Command Injection
  20,  // Improper Input Validation
  125, // Out-of-bounds Read
  22,  // Path Traversal
  352, // Cross-Site Request Forgery (CSRF)
  434, // Unrestricted Upload
  862, // Missing Authorization
  476, // NULL Pointer Dereference
  287, // Improper Authentication
  190, // Integer Overflow
  502, // Deserialization of Untrusted Data
  77,  // Command Injection
  119, // Buffer Overflow
  798, // Hardcoded Credentials
  918, // SSRF
  306, // Missing Authentication
  362, // Race Condition
  269, // Improper Privilege Management
  94,  // Code Injection
  863, // Incorrect Authorization
  276, // Incorrect Default Permissions
] as const;

export type CWEId = (typeof CWE_TOP_25)[number];

/**
 * Test Case Category (for generator modules)
 */
export interface TestCaseCategory {
  primary: string;
  owasp?: string;
  cwe?: string[];
  brdRequirement?: string;
}

/**
 * Generated Test Case (extended for generator modules)
 */
export interface GeneratedTestCase {
  id: string;
  name: string;
  description: string;
  type: 'security' | 'api' | 'functional' | 'performance' | 'integration' | 'load' | 'owasp';
  priority: 'critical' | 'high' | 'medium' | 'low';
  severity?: 'critical' | 'high' | 'medium' | 'low'; // alias for priority in some contexts
  category: TestCaseCategory | string; // Can be string for backward compatibility
  steps: string[];
  expectedResult: string;
  targetEndpoint?: Partial<ExtractedEndpoint>; // Partial to allow partial endpoint specs
  brdRequirementId?: string;
  metadata?: Record<string, unknown>;

  // Original fields for DB storage
  projectId?: string;
  codeAnalysisId?: string;
  brdAnalysisId?: string;
  title?: string; // alias for name
  owaspCategory?: OWASPCategory | string; // Allow string for flexibility
  cweId?: number;
  alignedRequirementId?: string;
  alignmentConfidence?: number;
  testPrompt?: string;
  target?: TestTarget;
  recommendedScanners?: string[];
  expectedSeverity?: 'critical' | 'high' | 'medium' | 'low';
  executed?: boolean;
  executionDate?: Date;
  scanResultId?: string;
}

export interface TestTarget {
  file?: string;
  endpoint?: string;
  function?: string;
  line?: number;
  module?: string;
  className?: string;
}

/**
 * Correlation between code and BRD
 */
export interface CorrelationResult {
  codeElement: {
    type: 'endpoint' | 'function' | 'dataflow' | 'auth' | 'class' | 'module';
    identifier: string;
    file: string;
    line?: number;
  };
  brdRequirement: BRDRequirement;
  confidence: number;
  reason: string;
  matchedKeywords?: string[];
}

// =============================================================================
// Service Options
// =============================================================================

/**
 * Analysis Options (used by code analyzer)
 */
export interface AnalysisOptions {
  includeDataFlow?: boolean;
  includeSensitiveData?: boolean;
  maxFileSize?: number;
  excludePatterns?: string[];
  includePatterns?: string[];
  timeout?: number;
  maxFiles?: number;
}

export interface CodeAnalyzerOptions {
  projectId: string;
  repositoryPath: string;
  repositoryUrl?: string;
  branch?: string;
  maxFileSize?: number;
  excludePatterns?: string[];
  includePatterns?: string[];
  timeout?: number;
  maxFiles?: number;
}

export interface BRDParserOptions {
  projectId: string;
  filePath?: string;
  buffer?: Buffer;
  fileName: string;
  mimeType: string;
  extractSecurityRequirements?: boolean;
}

export interface TestGeneratorOptions {
  projectId: string;
  codeAnalysis?: CodeAnalysisResult;
  brdAnalysis?: BRDAnalysisResult;
  codeAnalysisId?: string;
  brdAnalysisId?: string;
  categories?: ('owasp' | 'cwe' | 'brd_aligned')[];
  maxTestCases?: number;
  minConfidence?: number;
}

export interface TestExecutionOptions {
  testCaseIds: string[];
  projectId: string;
  scanProfile?: 'quick' | 'standard' | 'comprehensive';
  parallel?: boolean;
  timeout?: number;
}

// =============================================================================
// Service Interfaces
// =============================================================================

export interface ICodeAnalyzer {
  analyze(options: CodeAnalyzerOptions): Promise<CodeAnalysisResult>;
  detectLanguages(repoPath: string): Promise<LanguageDetection[]>;
  detectFrameworks(repoPath: string, languages: LanguageDetection[]): Promise<FrameworkDetection[]>;
  extractEndpoints(repoPath: string, frameworks: FrameworkDetection[]): Promise<ExtractedEndpoint[]>;
  detectAuthPatterns(repoPath: string): Promise<AuthPattern[]>;
  traceDataFlows(repoPath: string, endpoints: ExtractedEndpoint[]): Promise<DataFlow[]>;
  findSensitiveData(repoPath: string): Promise<SensitiveDataPoint[]>;
  parseDependencies(repoPath: string): Promise<Dependency[]>;
  detectInfrastructure(repoPath: string): Promise<InfrastructureFile[]>;
  generateSummary(result: Partial<CodeAnalysisResult>): Promise<CodeSummary>;
}

export interface IBRDParser {
  parse(options: BRDParserOptions): Promise<BRDAnalysisResult>;
  parseMarkdown(content: string): Promise<BRDRequirement[]>;
  parseDocx(buffer: Buffer): Promise<BRDRequirement[]>;
  parsePDF(buffer: Buffer): Promise<BRDRequirement[]>;
  extractSecurityRequirements(requirements: BRDRequirement[]): BRDRequirement[];
}

export interface ITestGenerator {
  generate(options: TestGeneratorOptions): Promise<GeneratedTestCase[]>;
  generateOWASPTests(codeAnalysis: CodeAnalysisResult): Promise<GeneratedTestCase[]>;
  generateCWETests(codeAnalysis: CodeAnalysisResult): Promise<GeneratedTestCase[]>;
  generateBRDAlignedTests(
    codeAnalysis: CodeAnalysisResult,
    brdAnalysis: BRDAnalysisResult
  ): Promise<GeneratedTestCase[]>;
  correlateCodeWithBRD(
    codeAnalysis: CodeAnalysisResult,
    brdAnalysis: BRDAnalysisResult
  ): Promise<CorrelationResult[]>;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Helper function to safely get TestCaseCategory as object
 * Handles the union type `string | TestCaseCategory`
 */
export function getCategoryObject(category: string | TestCaseCategory): TestCaseCategory {
  if (typeof category === 'string') {
    return { primary: category };
  }
  return category;
}

/**
 * Helper to get category primary value as string
 */
export function getCategoryPrimary(category: string | TestCaseCategory): string {
  if (typeof category === 'string') {
    return category;
  }
  return category.primary;
}
