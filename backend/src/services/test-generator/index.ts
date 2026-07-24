/**
 * Test Generator Service
 * Main entry point for BRD-to-test-case generation
 *
 * This service provides:
 * - Code analysis (language, framework, security pattern detection)
 * - BRD parsing (Markdown, DOCX, PDF)
 * - Test case generation based on OWASP Top 10 and CWE Top 25
 * - BRD requirement alignment and coverage tracking
 */

import { createLogger } from '../../utils/logger.js';

// Import sub-modules
import * as codeAnalyzer from './code-analyzer/index.js';
import * as brdParser from './brd-parser/index.js';
import * as generator from './generator/index.js';

// Import types
import type {
  CodeAnalysisResult,
  BRDAnalysisResult,
  GeneratedTestCase,
  ParsedRequirement,
  ExtractedEndpoint,
  AnalysisOptions,
} from './types.js';

const logger = createLogger('test-generator-service');

export interface TestGeneratorOptions {
  /** Code analysis options */
  analysis?: AnalysisOptions;
  /** BRD parsing options */
  brd?: brdParser.ParseOptions;
  /** Test generation options */
  generation?: generator.GenerationOptions;
}

export interface FullTestGeneratorResult {
  /** Code analysis results */
  codeAnalysis: codeAnalyzer.FullAnalysisResult;
  /** BRD analysis results (if BRD provided) */
  brdAnalysis?: BRDAnalysisResult;
  /** Generated test cases */
  testGeneration: generator.FullGenerationResult;
  /** Execution metadata */
  metadata: {
    startedAt: string;
    completedAt: string;
    duration: number;
    repoPath?: string;
    brdPath?: string;
  };
}

/**
 * Generate test cases from a code repository
 */
export async function generateFromRepo(
  repoPath: string,
  options: TestGeneratorOptions = {}
): Promise<FullTestGeneratorResult> {
  logger.info({ repoPath }, 'Starting test generation from repository');
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Step 1: Analyze code
  const codeAnalysis = await codeAnalyzer.analyzeCode(repoPath, options.analysis);

  // Step 2: Generate test cases
  const testGeneration = await generator.generateTestCases(
    codeAnalysis.result,
    codeAnalysis.result.endpoints,
    [], // No BRD requirements
    options.generation
  );

  const completedAt = new Date().toISOString();

  logger.info(
    {
      repoPath,
      testCount: testGeneration.testCases.length,
      duration: Date.now() - startTime,
    },
    'Test generation from repository completed'
  );

  return {
    codeAnalysis,
    testGeneration,
    metadata: {
      startedAt,
      completedAt,
      duration: Date.now() - startTime,
      repoPath,
    },
  };
}

/**
 * Generate test cases from code repository and BRD document
 */
export async function generateFromRepoAndBrd(
  repoPath: string,
  brdPath: string,
  options: TestGeneratorOptions = {}
): Promise<FullTestGeneratorResult> {
  logger.info({ repoPath, brdPath }, 'Starting test generation from repository and BRD');
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Step 1: Analyze code
  const codeAnalysis = await codeAnalyzer.analyzeCode(repoPath, options.analysis);

  // Step 2: Parse BRD
  const brdParseResult = await brdParser.parseBRDFile(brdPath, options.brd);
  const brdAnalysis = brdParser.createBRDAnalysisResult(brdParseResult, brdPath);

  // Step 3: Generate test cases with BRD alignment
  const testGeneration = await generator.generateTestCases(
    codeAnalysis.result,
    codeAnalysis.result.endpoints,
    brdParseResult.requirements,
    {
      ...options.generation,
      alignWithBrd: true,
      fillGaps: true,
    }
  );

  const completedAt = new Date().toISOString();

  logger.info(
    {
      repoPath,
      brdPath,
      testCount: testGeneration.testCases.length,
      requirementCount: brdParseResult.requirements.length,
      duration: Date.now() - startTime,
    },
    'Test generation from repository and BRD completed'
  );

  return {
    codeAnalysis,
    brdAnalysis,
    testGeneration,
    metadata: {
      startedAt,
      completedAt,
      duration: Date.now() - startTime,
      repoPath,
      brdPath,
    },
  };
}

/**
 * Generate test cases from BRD document only
 */
export async function generateFromBrd(
  brdPath: string,
  options: TestGeneratorOptions = {}
): Promise<{
  brdAnalysis: BRDAnalysisResult;
  testCases: GeneratedTestCase[];
  metadata: {
    startedAt: string;
    completedAt: string;
    duration: number;
    brdPath: string;
  };
}> {
  logger.info({ brdPath }, 'Starting test generation from BRD only');
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Parse BRD
  const brdParseResult = await brdParser.parseBRDFile(brdPath, options.brd);
  const brdAnalysis = brdParser.createBRDAnalysisResult(brdParseResult, brdPath);

  // Generate requirement-based tests without code analysis
  const testCases = generateRequirementBasedTests(brdParseResult.requirements);

  const completedAt = new Date().toISOString();

  logger.info(
    {
      brdPath,
      testCount: testCases.length,
      requirementCount: brdParseResult.requirements.length,
      duration: Date.now() - startTime,
    },
    'Test generation from BRD completed'
  );

  return {
    brdAnalysis,
    testCases,
    metadata: {
      startedAt,
      completedAt,
      duration: Date.now() - startTime,
      brdPath,
    },
  };
}

/**
 * Generate test cases from BRD content string
 */
export function generateFromBrdContent(
  brdContent: string,
  options: TestGeneratorOptions = {}
): {
  brdAnalysis: BRDAnalysisResult;
  testCases: GeneratedTestCase[];
} {
  logger.info('Starting test generation from BRD content');

  // Parse BRD content
  const brdParseResult = brdParser.parseBRDContent(brdContent, options.brd);
  const brdAnalysis = brdParser.createBRDAnalysisResult(brdParseResult, 'inline');

  // Generate requirement-based tests
  const testCases = generateRequirementBasedTests(brdParseResult.requirements);

  logger.info(
    {
      testCount: testCases.length,
      requirementCount: brdParseResult.requirements.length,
    },
    'Test generation from BRD content completed'
  );

  return {
    brdAnalysis,
    testCases,
  };
}

/**
 * Analyze code without generating tests
 */
export async function analyzeCode(
  repoPath: string,
  options?: AnalysisOptions
): Promise<codeAnalyzer.FullAnalysisResult> {
  return codeAnalyzer.analyzeCode(repoPath, options);
}

/**
 * Quick code analysis (faster, less detailed)
 */
export async function analyzeCodeQuick(
  repoPath: string
): Promise<codeAnalyzer.FullAnalysisResult> {
  return codeAnalyzer.analyzeCodeQuick(repoPath);
}

/**
 * Security-focused code analysis
 */
export async function analyzeCodeSecurity(
  repoPath: string
): Promise<codeAnalyzer.FullAnalysisResult> {
  return codeAnalyzer.analyzeCodeSecurity(repoPath);
}

/**
 * Parse BRD file
 */
export async function parseBrd(
  filePath: string,
  options?: brdParser.ParseOptions
): Promise<brdParser.ParseResult> {
  return brdParser.parseBRDFile(filePath, options);
}

/**
 * Parse BRD content string
 */
export function parseBrdContent(
  content: string,
  options?: brdParser.ParseOptions
): brdParser.ParseResult {
  return brdParser.parseBRDContent(content, options);
}

/**
 * Generate tests from existing analysis results
 */
export async function generateTests(
  codeAnalysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[],
  requirements: ParsedRequirement[] = [],
  options?: generator.GenerationOptions
): Promise<generator.FullGenerationResult> {
  return generator.generateTestCases(codeAnalysis, endpoints, requirements, options);
}

/**
 * Generate requirement-based test cases without code analysis
 */
function generateRequirementBasedTests(
  requirements: ParsedRequirement[]
): GeneratedTestCase[] {
  const testCases: GeneratedTestCase[] = [];

  for (const req of requirements) {
    // Create a basic test case for each requirement
    testCases.push({
      id: `REQ-TEST-${req.id}`,
      name: `Verify: ${req.title}`,
      description: `Test case to verify requirement ${req.id}: ${req.description.substring(0, 200)}`,
      type: req.type === 'security' ? 'security' : req.type === 'api' ? 'api' : 'functional',
      priority: req.priority,
      category: {
        primary: req.id,
        brdRequirement: req.id,
      },
      steps: generateStepsFromRequirement(req),
      expectedResult: `Requirement ${req.id} is satisfied`,
      brdRequirementId: req.id,
      metadata: {
        requirementType: req.type,
        requirementPriority: req.priority,
      },
    });

    // Add acceptance criteria tests
    const acceptanceCriteria = req.acceptanceCriteria || [];
    for (let i = 0; i < acceptanceCriteria.length; i++) {
      const criterion = acceptanceCriteria[i];
      testCases.push({
        id: `REQ-TEST-${req.id}-AC${i + 1}`,
        name: `Verify AC${i + 1}: ${criterion.substring(0, 50)}`,
        description: `Test acceptance criterion ${i + 1} for ${req.id}`,
        type: req.type === 'security' ? 'security' : 'functional',
        priority: req.priority,
        category: {
          primary: req.id,
          brdRequirement: req.id,
        },
        steps: [
          'Setup test environment',
          `Execute: ${criterion}`,
          'Verify expected outcome',
        ],
        expectedResult: criterion,
        brdRequirementId: req.id,
        metadata: {
          acceptanceCriterion: i + 1,
        },
      });
    }
  }

  return testCases;
}

/**
 * Generate test steps from requirement
 */
function generateStepsFromRequirement(req: ParsedRequirement): string[] {
  const steps: string[] = [];

  if (req.userStory) {
    steps.push(`Setup: Configure system for ${req.userStory.role} role`);
    steps.push(`Action: ${req.userStory.feature}`);
    steps.push(`Verify: ${req.userStory.benefit}`);
  } else {
    steps.push('Review requirement description');
    steps.push('Identify testable conditions');
    steps.push('Execute test scenario');
    steps.push('Verify expected behavior');
  }

  return steps;
}

// Re-export types
export type {
  CodeAnalysisResult,
  BRDAnalysisResult,
  TestGenerationResult,
  GeneratedTestCase,
  ParsedRequirement,
  ExtractedEndpoint,
  AnalysisOptions,
  LanguageDetection,
  FrameworkDetection,
  AuthPattern,
  DataFlow,
  SensitiveDataPoint,
  Dependency,
  InfrastructureFile,
  CodeSummary,
  BRDSection,
  BRDRequirement,
  OWASPCategory,
  CorrelationResult,
  RequirementType,
  RequirementSource,
} from './types.js';

// Re-export sub-modules
export { codeAnalyzer, brdParser, generator };

// Re-export commonly used functions
export {
  // From code-analyzer
  detectLanguages,
  detectFrameworks,
  extractEndpoints,
} from './code-analyzer/index.js';

export {
  // From brd-parser
  parseMarkdownFile,
  parseDocxFile,
  parsePdfFile,
  extractRequirements,
} from './brd-parser/index.js';

export {
  // From generator
  generateOwaspTestCases,
  generateCweTestCases,
  alignTestsWithRequirements,
  correlateFindings,
  generateOutput,
  generatePrompt,
  OWASP_TOP_10_2021,
  CWE_TOP_25_2023,
} from './generator/index.js';
