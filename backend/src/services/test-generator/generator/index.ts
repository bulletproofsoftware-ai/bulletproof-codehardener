/**
 * Test Generator Module
 * Orchestrates OWASP, CWE, BRD-based test case generation
 */

import { createLogger } from '../../../utils/logger.js';
import type {
  GeneratedTestCase,
  ParsedRequirement,
  CodeAnalysisResult,
  ExtractedEndpoint,
  TestGenerationResult,
} from '../types.js';
import { getCategoryObject } from '../types.js';

// Import generators
import {
  generateOwaspTestCases,
  getOwaspCoverage,
  OWASP_TOP_10_2021,
} from './owasp-generator.js';

import {
  generateCweTestCases,
  getCweCoverage,
  getCweByRank,
  getApplicableCweForLanguages,
  CWE_TOP_25_2023,
} from './cwe-generator.js';

import {
  alignTestsWithRequirements,
  generateGapFillingTests,
  getCoverageReport,
  type AlignmentResult,
} from './brd-alignment.js';

import {
  correlateFindings,
  getUnifiedCoverageReport,
  OWASP_TO_CWE_MAP,
  CWE_TO_OWASP_MAP,
  type CorrelationResult,
} from './correlation-engine.js';

import {
  generateOutput,
  generateCoverageReport,
  type OutputFormat,
  type TemplateOptions,
  type TemplateResult,
} from './template-engine.js';

import {
  generatePrompt,
  generateSummaryPrompt,
  parseTestCaseResponse,
  type PromptType,
  type PromptContext,
  type GeneratedPrompt,
} from './prompt-generator.js';

const logger = createLogger('test-generator');

export interface GenerationOptions {
  /** Include OWASP Top 10 based tests */
  includeOwasp?: boolean;
  /** Include CWE Top 25 based tests */
  includeCwe?: boolean;
  /** Align tests with BRD requirements */
  alignWithBrd?: boolean;
  /** Generate gap-filling tests for unmapped requirements */
  fillGaps?: boolean;
  /** Output format */
  outputFormat?: OutputFormat;
  /** Focus on specific OWASP categories */
  owaspFocus?: string[];
  /** Focus on specific CWE IDs */
  cweFocus?: string[];
  /** Maximum test cases to generate */
  maxTestCases?: number;
  /** Include AI prompts for further refinement */
  includePrompts?: boolean;
}

export interface FullGenerationResult {
  /** Generated test cases */
  testCases: GeneratedTestCase[];
  /** OWASP-based tests */
  owaspTests: GeneratedTestCase[];
  /** CWE-based tests */
  cweTests: GeneratedTestCase[];
  /** Gap-filling tests */
  gapTests: GeneratedTestCase[];
  /** BRD alignment results */
  alignment?: AlignmentResult;
  /** Cross-framework correlation */
  correlation?: CorrelationResult;
  /** Coverage metrics */
  coverage: {
    owasp: Record<string, number>;
    cwe: Record<string, number>;
    overall: number;
    recommendations: string[];
  };
  /** Formatted output */
  output?: TemplateResult;
  /** AI prompts for refinement */
  prompts?: GeneratedPrompt[];
  /** Generation metadata */
  metadata: {
    generatedAt: string;
    duration: number;
    options: GenerationOptions;
    stats: {
      totalTests: number;
      byType: Record<string, number>;
      byPriority: Record<string, number>;
    };
  };
}

/**
 * Generate comprehensive test cases from code analysis and BRD
 */
export async function generateTestCases(
  codeAnalysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[],
  requirements: ParsedRequirement[] = [],
  options: GenerationOptions = {}
): Promise<FullGenerationResult> {
  logger.info(
    {
      languageCount: codeAnalysis.languages.length,
      endpointCount: endpoints.length,
      requirementCount: requirements.length,
      options,
    },
    'Starting test case generation'
  );

  const startTime = Date.now();

  // Set defaults
  const opts: Required<GenerationOptions> = {
    includeOwasp: options.includeOwasp ?? true,
    includeCwe: options.includeCwe ?? true,
    alignWithBrd: options.alignWithBrd ?? requirements.length > 0,
    fillGaps: options.fillGaps ?? true,
    outputFormat: options.outputFormat ?? 'json',
    owaspFocus: options.owaspFocus ?? [],
    cweFocus: options.cweFocus ?? [],
    maxTestCases: options.maxTestCases ?? 0,
    includePrompts: options.includePrompts ?? false,
  };

  // Generate OWASP-based tests
  let owaspTests: GeneratedTestCase[] = [];
  if (opts.includeOwasp) {
    owaspTests = generateOwaspTestCases(codeAnalysis, endpoints);

    // Filter by focus if specified
    if (opts.owaspFocus.length > 0) {
      owaspTests = owaspTests.filter(t => {
        const cat = getCategoryObject(t.category);
        return cat.owasp && opts.owaspFocus.includes(cat.owasp);
      });
    }

    logger.info({ count: owaspTests.length }, 'Generated OWASP tests');
  }

  // Generate CWE-based tests
  let cweTests: GeneratedTestCase[] = [];
  if (opts.includeCwe) {
    cweTests = generateCweTestCases(codeAnalysis, endpoints);

    // Filter by focus if specified
    if (opts.cweFocus.length > 0) {
      cweTests = cweTests.filter(t => {
        const cat = getCategoryObject(t.category);
        return cat.cwe && cat.cwe.some((cwe: string) => opts.cweFocus.includes(cwe));
      });
    }

    logger.info({ count: cweTests.length }, 'Generated CWE tests');
  }

  // Combine and deduplicate
  let allTests = deduplicateTests([...owaspTests, ...cweTests]);

  // Align with BRD requirements
  let alignment: AlignmentResult | undefined;
  let gapTests: GeneratedTestCase[] = [];

  if (opts.alignWithBrd && requirements.length > 0) {
    alignment = alignTestsWithRequirements(allTests, requirements);

    // Generate gap-filling tests
    if (opts.fillGaps) {
      gapTests = generateGapFillingTests(alignment);
      allTests = deduplicateTests([...allTests, ...gapTests]);
    }

    logger.info(
      {
        covered: alignment.overallCoverage.coveredRequirements,
        total: alignment.overallCoverage.totalRequirements,
        gapTestsGenerated: gapTests.length,
      },
      'BRD alignment completed'
    );
  }

  // Apply max limit if specified
  if (opts.maxTestCases > 0 && allTests.length > opts.maxTestCases) {
    // Prioritize by priority, then by type (security first)
    allTests = prioritizeAndLimit(allTests, opts.maxTestCases);
  }

  // Correlate findings across frameworks
  const correlation = correlateFindings(allTests, requirements, codeAnalysis, endpoints);

  // Calculate coverage
  const owaspCoverage = getOwaspCoverage(allTests);
  const cweCoverage = getCweCoverage(allTests);
  const coverageReport = getUnifiedCoverageReport(correlation);

  // Generate output
  const output = generateOutput(allTests, {
    format: opts.outputFormat,
    includeMetadata: true,
    includeSteps: true,
  });

  // Generate prompts if requested
  let prompts: GeneratedPrompt[] | undefined;
  if (opts.includePrompts) {
    prompts = [
      generatePrompt('coverage_analysis', {
        analysis: codeAnalysis,
        endpoints,
        requirements,
        existingTests: allTests,
      }),
      generatePrompt('security_review', {
        analysis: codeAnalysis,
        endpoints,
        existingTests: allTests,
      }),
    ];
  }

  // Build stats
  const stats = {
    totalTests: allTests.length,
    byType: {} as Record<string, number>,
    byPriority: {} as Record<string, number>,
  };

  for (const test of allTests) {
    stats.byType[test.type] = (stats.byType[test.type] || 0) + 1;
    stats.byPriority[test.priority] = (stats.byPriority[test.priority] || 0) + 1;
  }

  const result: FullGenerationResult = {
    testCases: allTests,
    owaspTests,
    cweTests,
    gapTests,
    alignment,
    correlation,
    coverage: {
      owasp: owaspCoverage,
      cwe: cweCoverage,
      overall: coverageReport.overallScore,
      recommendations: coverageReport.criticalGaps,
    },
    output,
    prompts,
    metadata: {
      generatedAt: new Date().toISOString(),
      duration: Date.now() - startTime,
      options: opts,
      stats,
    },
  };

  logger.info(
    {
      totalTests: allTests.length,
      duration: result.metadata.duration,
      owaspCoverage: Object.keys(owaspCoverage).length,
      cweCoverage: Object.keys(cweCoverage).length,
      overallCoverage: coverageReport.overallScore,
    },
    'Test case generation completed'
  );

  return result;
}

/**
 * Quick generation focused on security tests only
 */
export function generateSecurityTests(
  codeAnalysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[]
): GeneratedTestCase[] {
  logger.info('Generating security-focused tests');

  const owaspTests = generateOwaspTestCases(codeAnalysis, endpoints);
  const cweTests = generateCweTestCases(codeAnalysis, endpoints);

  // Combine and filter to security type only
  const allTests = deduplicateTests([...owaspTests, ...cweTests])
    .filter(t => t.type === 'security');

  logger.info({ count: allTests.length }, 'Security tests generated');
  return allTests;
}

/**
 * Generate tests for specific OWASP categories
 */
export function generateOwaspFocusedTests(
  codeAnalysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[],
  categories: string[]
): GeneratedTestCase[] {
  logger.info({ categories }, 'Generating OWASP-focused tests');

  const allTests = generateOwaspTestCases(codeAnalysis, endpoints);
  const filtered = allTests.filter(t => {
    const cat = getCategoryObject(t.category);
    return cat.owasp && categories.includes(cat.owasp);
  });

  logger.info({ count: filtered.length }, 'OWASP-focused tests generated');
  return filtered;
}

/**
 * Generate tests for specific CWE IDs
 */
export function generateCweFocusedTests(
  codeAnalysis: CodeAnalysisResult,
  endpoints: ExtractedEndpoint[],
  cweIds: string[]
): GeneratedTestCase[] {
  logger.info({ cweIds }, 'Generating CWE-focused tests');

  const allTests = generateCweTestCases(codeAnalysis, endpoints);
  const filtered = allTests.filter(t => {
    const cat = getCategoryObject(t.category);
    return cat.cwe && cat.cwe.some((cwe: string) => cweIds.includes(cwe));
  });

  logger.info({ count: filtered.length }, 'CWE-focused tests generated');
  return filtered;
}

/**
 * Create test generation result from existing tests
 */
export function createTestGenerationResult(
  testCases: GeneratedTestCase[],
  sourceFile: string
): TestGenerationResult {
  const owaspCoverage = getOwaspCoverage(testCases);
  const cweCoverage = getCweCoverage(testCases);

  return {
    testCases,
    coverage: {
      owasp: owaspCoverage,
      cwe: cweCoverage,
      overall: calculateOverallCoverage(owaspCoverage, cweCoverage),
    },
    sourceFile,
  };
}

/**
 * Deduplicate test cases based on similarity
 */
function deduplicateTests(testCases: GeneratedTestCase[]): GeneratedTestCase[] {
  const unique: GeneratedTestCase[] = [];
  const seenSignatures = new Set<string>();

  for (const tc of testCases) {
    // Create a signature from key fields
    const cat = getCategoryObject(tc.category);
    const signature = [
      cat.owasp || '',
      cat.cwe?.join(',') || '',
      tc.targetEndpoint?.method || '',
      tc.targetEndpoint?.path || '',
      tc.name.toLowerCase().replace(/\s+/g, '-').substring(0, 50),
    ].join('|');

    if (!seenSignatures.has(signature)) {
      seenSignatures.add(signature);
      unique.push(tc);
    }
  }

  return unique;
}

/**
 * Prioritize and limit test cases
 */
function prioritizeAndLimit(
  testCases: GeneratedTestCase[],
  limit: number
): GeneratedTestCase[] {
  const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const typeOrder: Record<string, number> = { security: 0, api: 1, functional: 2, performance: 3, integration: 4, load: 5, owasp: 0 };

  return testCases
    .sort((a, b) => {
      // First by priority
      const prioDiff = (priorityOrder[a.priority] ?? 99) - (priorityOrder[b.priority] ?? 99);
      if (prioDiff !== 0) return prioDiff;

      // Then by type (security first)
      const typeDiff = (typeOrder[a.type] ?? 99) - (typeOrder[b.type] ?? 99);
      return typeDiff;
    })
    .slice(0, limit);
}

/**
 * Calculate overall coverage percentage
 */
function calculateOverallCoverage(
  owaspCoverage: Record<string, number>,
  cweCoverage: Record<string, number>
): number {
  const owaspTotal = Object.keys(OWASP_TOP_10_2021).length;
  const cweTotal = Object.keys(CWE_TOP_25_2023).length;

  const owaspCovered = Object.keys(owaspCoverage).length;
  const cweCovered = Object.keys(cweCoverage).length;

  // Weighted average (OWASP 50%, CWE 50%)
  const owaspPercent = owaspTotal > 0 ? (owaspCovered / owaspTotal) * 100 : 0;
  const cwePercent = cweTotal > 0 ? (cweCovered / cweTotal) * 100 : 0;

  return Math.round((owaspPercent * 0.5) + (cwePercent * 0.5));
}

// Re-export types and utilities
export {
  // OWASP
  generateOwaspTestCases,
  getOwaspCoverage,
  OWASP_TOP_10_2021,

  // CWE
  generateCweTestCases,
  getCweCoverage,
  getCweByRank,
  getApplicableCweForLanguages,
  CWE_TOP_25_2023,

  // BRD Alignment
  alignTestsWithRequirements,
  generateGapFillingTests,
  getCoverageReport,
  type AlignmentResult,

  // Correlation
  correlateFindings,
  getUnifiedCoverageReport,
  OWASP_TO_CWE_MAP,
  CWE_TO_OWASP_MAP,
  type CorrelationResult,

  // Templates
  generateOutput,
  generateCoverageReport,
  type OutputFormat,
  type TemplateOptions,
  type TemplateResult,

  // Prompts
  generatePrompt,
  generateSummaryPrompt,
  parseTestCaseResponse,
  type PromptType,
  type PromptContext,
  type GeneratedPrompt,
};
