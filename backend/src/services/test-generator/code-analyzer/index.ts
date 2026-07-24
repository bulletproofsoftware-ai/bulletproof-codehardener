/**
 * Code Analyzer Orchestrator
 * Coordinates all code analysis modules (CA-001 to CA-010)
 */

import * as fs from 'fs/promises';
import { createLogger } from '../../../utils/logger.js';
import type { CodeAnalysisResult } from '../types.js';

// Import all analyzer modules
import { detectLanguages } from './language-detector.js';
import { detectFrameworks } from './framework-detector.js';
import { extractEndpoints } from './endpoint-extractor.js';
import { detectAuthPatterns } from './auth-detector.js';
import { traceDataFlows } from './dataflow-tracer.js';
import { findSensitiveData } from './sensitive-data.js';
import { parseDependencies } from './dependency-parser.js';
import { detectInfrastructure } from './infra-detector.js';
import { generateSummary, calculateSecurityScore } from './summary-generator.js';
import {
  scanRepository,
  getAnalysisConfig,
  estimateMemoryUsage,
  AnalysisProgressTracker,
  type RepoStats,
} from './large-repo-handler.js';

const logger = createLogger('code-analyzer');

export interface AnalysisOptions {
  /** Skip language detection (use provided languages) */
  skipLanguageDetection?: boolean;
  /** Languages to analyze (if skipLanguageDetection is true) */
  languages?: string[];
  /** Skip framework detection */
  skipFrameworkDetection?: boolean;
  /** Skip endpoint extraction */
  skipEndpointExtraction?: boolean;
  /** Skip auth pattern detection */
  skipAuthDetection?: boolean;
  /** Skip data flow tracing */
  skipDataFlowTracing?: boolean;
  /** Skip sensitive data detection */
  skipSensitiveDataDetection?: boolean;
  /** Skip dependency parsing */
  skipDependencyParsing?: boolean;
  /** Skip infrastructure detection */
  skipInfraDetection?: boolean;
  /** Force full analysis even for large repos */
  forceFullAnalysis?: boolean;
  /** Custom timeout in milliseconds */
  timeout?: number;
  /** Progress callback */
  onProgress?: (step: string, progress: number) => void;
}

export interface AnalysisMetadata {
  repoPath: string;
  startTime: number;
  endTime: number;
  durationMs: number;
  repoStats: RepoStats;
  analysisStrategy: 'full' | 'chunked' | 'sampled';
  memoryEstimate: {
    estimatedMB: number;
    isMemorySafe: boolean;
  };
  skippedModules: string[];
  errors: Array<{ module: string; error: string }>;
}

export interface FullAnalysisResult {
  result: CodeAnalysisResult;
  metadata: AnalysisMetadata;
}

/**
 * Validate repository path exists and is accessible
 */
async function validateRepoPath(repoPath: string): Promise<void> {
  try {
    const stats = await fs.stat(repoPath);
    if (!stats.isDirectory()) {
      throw new Error(`Path is not a directory: ${repoPath}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`Repository path does not exist: ${repoPath}`);
    }
    throw error;
  }
}

/**
 * Analyze code repository
 * Main entry point for code analysis
 */
export async function analyzeCode(
  repoPath: string,
  options: AnalysisOptions = {}
): Promise<FullAnalysisResult> {
  const startTime = Date.now();
  const errors: Array<{ module: string; error: string }> = [];
  const skippedModules: string[] = [];

  logger.info({ repoPath, options }, 'Starting code analysis');

  // Validate repository path
  await validateRepoPath(repoPath);

  // Scan repository for statistics
  const repoStats = await scanRepository(repoPath);
  const memoryEstimate = estimateMemoryUsage(repoStats);
  const analysisConfig = getAnalysisConfig(repoStats);

  // Determine analysis strategy
  let analysisStrategy = analysisConfig.strategy;
  if (options.forceFullAnalysis) {
    analysisStrategy = 'full';
    logger.warn({ repoStats }, 'Forcing full analysis on large repository');
  }

  logger.info(
    {
      repoPath,
      totalFiles: repoStats.totalFiles,
      totalSizeMB: Math.round(repoStats.totalSize / 1024 / 1024),
      analysisStrategy,
      memoryEstimateMB: memoryEstimate.estimatedMB,
    },
    'Repository scanned, starting analysis'
  );

  // Initialize progress tracker
  const totalSteps = 9; // One for each analysis module
  const tracker = new AnalysisProgressTracker(totalSteps);

  // Initialize result object
  const result: CodeAnalysisResult = {
    id: `ca-${Date.now()}-${crypto.randomUUID().replace(/-/g, '').substring(0, 9)}`,
    projectId: '', // To be set by caller
    analysisDate: new Date(),
    status: 'processing',
    languages: [],
    frameworks: [],
    endpoints: [],
    authPatterns: [],
    dataFlows: [],
    sensitiveData: [],
    dependencies: [],
    infrastructure: [],
    summary: {
      totalFiles: 0,
      totalLinesOfCode: 0,
      languages: [],
      frameworks: [],
      entryPoints: [],
      securityConcerns: [],
      complexity: 'simple',
    },
  };

  // Step 1: Language Detection (CA-001)
  if (!options.skipLanguageDetection) {
    tracker.startStep('Language Detection');
    try {
      result.languages = await detectLanguages(repoPath);
      options.onProgress?.('Language Detection', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'language-detector', error: errorMsg });
      logger.error({ error: errorMsg }, 'Language detection failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('language-detector');
  }

  // Step 2: Framework Detection (CA-002)
  if (!options.skipFrameworkDetection) {
    tracker.startStep('Framework Detection');
    try {
      result.frameworks = await detectFrameworks(repoPath, result.languages);
      options.onProgress?.('Framework Detection', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'framework-detector', error: errorMsg });
      logger.error({ error: errorMsg }, 'Framework detection failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('framework-detector');
  }

  // Step 3: Endpoint Extraction (CA-003)
  if (!options.skipEndpointExtraction) {
    tracker.startStep('Endpoint Extraction');
    try {
      result.endpoints = await extractEndpoints(repoPath, result.frameworks);
      options.onProgress?.('Endpoint Extraction', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'endpoint-extractor', error: errorMsg });
      logger.error({ error: errorMsg }, 'Endpoint extraction failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('endpoint-extractor');
  }

  // Step 4: Auth Pattern Detection (CA-004)
  if (!options.skipAuthDetection) {
    tracker.startStep('Auth Pattern Detection');
    try {
      result.authPatterns = await detectAuthPatterns(repoPath);
      options.onProgress?.('Auth Pattern Detection', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'auth-detector', error: errorMsg });
      logger.error({ error: errorMsg }, 'Auth pattern detection failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('auth-detector');
  }

  // Step 5: Data Flow Tracing (CA-005)
  if (!options.skipDataFlowTracing) {
    tracker.startStep('Data Flow Tracing');
    try {
      result.dataFlows = await traceDataFlows(repoPath, result.endpoints);
      options.onProgress?.('Data Flow Tracing', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'dataflow-tracer', error: errorMsg });
      logger.error({ error: errorMsg }, 'Data flow tracing failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('dataflow-tracer');
  }

  // Step 6: Sensitive Data Detection (CA-006)
  if (!options.skipSensitiveDataDetection) {
    tracker.startStep('Sensitive Data Detection');
    try {
      result.sensitiveData = await findSensitiveData(repoPath);
      options.onProgress?.('Sensitive Data Detection', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'sensitive-data', error: errorMsg });
      logger.error({ error: errorMsg }, 'Sensitive data detection failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('sensitive-data');
  }

  // Step 7: Dependency Parsing (CA-007)
  if (!options.skipDependencyParsing) {
    tracker.startStep('Dependency Parsing');
    try {
      result.dependencies = await parseDependencies(repoPath);
      options.onProgress?.('Dependency Parsing', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'dependency-parser', error: errorMsg });
      logger.error({ error: errorMsg }, 'Dependency parsing failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('dependency-parser');
  }

  // Step 8: Infrastructure Detection (CA-008)
  if (!options.skipInfraDetection) {
    tracker.startStep('Infrastructure Detection');
    try {
      result.infrastructure = await detectInfrastructure(repoPath);
      options.onProgress?.('Infrastructure Detection', tracker.getProgress().percentage);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push({ module: 'infra-detector', error: errorMsg });
      logger.error({ error: errorMsg }, 'Infrastructure detection failed');
    }
    tracker.completeStep();
  } else {
    skippedModules.push('infra-detector');
  }

  // Step 9: Generate Summary (CA-009)
  tracker.startStep('Summary Generation');
  try {
    result.summary = generateSummary(result);
    options.onProgress?.('Summary Generation', tracker.getProgress().percentage);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    errors.push({ module: 'summary-generator', error: errorMsg });
    logger.error({ error: errorMsg }, 'Summary generation failed');
  }
  tracker.completeStep();

  const endTime = Date.now();
  const durationMs = endTime - startTime;

  // Update status to completed
  result.status = 'completed';
  result.processingTimeMs = durationMs;

  const metadata: AnalysisMetadata = {
    repoPath,
    startTime,
    endTime,
    durationMs,
    repoStats,
    analysisStrategy,
    memoryEstimate: {
      estimatedMB: memoryEstimate.estimatedMB,
      isMemorySafe: memoryEstimate.isMemorySafe,
    },
    skippedModules,
    errors,
  };

  logger.info(
    {
      repoPath,
      durationMs,
      languageCount: result.languages.length,
      frameworkCount: result.frameworks.length,
      endpointCount: result.endpoints.length,
      authPatternCount: result.authPatterns.length,
      dataFlowCount: result.dataFlows.length,
      sensitiveDataCount: result.sensitiveData.length,
      dependencyCount: result.dependencies.length,
      infraCount: result.infrastructure.length,
      securityConcernCount: result.summary.securityConcerns.length,
      securityScore: calculateSecurityScore(result.summary),
      errorCount: errors.length,
    },
    'Code analysis completed'
  );

  return { result, metadata };
}

/**
 * Quick analysis - skips time-intensive modules
 */
export async function analyzeCodeQuick(
  repoPath: string
): Promise<FullAnalysisResult> {
  return analyzeCode(repoPath, {
    skipDataFlowTracing: true,
    skipSensitiveDataDetection: true,
  });
}

/**
 * Security-focused analysis
 */
export async function analyzeCodeSecurity(
  repoPath: string
): Promise<FullAnalysisResult> {
  return analyzeCode(repoPath, {
    skipInfraDetection: false,
  });
}

// Re-export all sub-modules for direct access
export * from './language-detector.js';
export * from './framework-detector.js';
export * from './endpoint-extractor.js';
export * from './auth-detector.js';
export * from './dataflow-tracer.js';
export * from './sensitive-data.js';
export * from './dependency-parser.js';
export * from './infra-detector.js';
export * from './summary-generator.js';
export * from './large-repo-handler.js';
