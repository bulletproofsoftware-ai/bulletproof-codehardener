/**
 * Code Analysis Integration for Finding Enrichment
 *
 * Thin wrapper around the test-generator's analyzeCode() that runs a
 * security-focused subset of CA modules on /scan-target during the scan
 * pipeline. Results feed into the enrichment layer (framework suppressions,
 * reachability filtering, dataflow cross-referencing, exploitability scoring).
 *
 * Skips modules redundant with existing scanners:
 *   - Sensitive data detection → Gitleaks handles this
 *   - Dependency parsing → Trivy/Grype handle this
 *   - Infrastructure detection → Checkov handles this
 *
 * Runs: CA-001 (languages), CA-002 (frameworks), CA-003 (endpoints),
 *        CA-004 (auth patterns), CA-005 (dataflows)
 */

import { analyzeCode, type FullAnalysisResult } from '../test-generator/code-analyzer/index.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('code-analysis');

export type { FullAnalysisResult };

export async function runCodeAnalysis(scanTarget: string): Promise<FullAnalysisResult | null> {
  const startTime = Date.now();
  try {
    const result = await analyzeCode(scanTarget, {
      skipSensitiveDataDetection: true,  // Gitleaks handles this
      skipDependencyParsing: true,        // Trivy/Grype handle this
      skipInfraDetection: true,           // Checkov handles this
      timeout: 30000,                     // 30s max
    });

    logger.info(
      {
        durationMs: Date.now() - startTime,
        languages: result.result.languages.length,
        frameworks: result.result.frameworks.length,
        endpoints: result.result.endpoints.length,
        authPatterns: result.result.authPatterns.length,
        dataFlows: result.result.dataFlows.length,
      },
      'Code analysis completed for enrichment'
    );

    return result;
  } catch (error) {
    logger.warn(
      { error: error instanceof Error ? error.message : 'Unknown error', durationMs: Date.now() - startTime },
      'Code analysis failed — enrichment will be skipped (non-fatal)'
    );
    return null;  // Non-fatal — enrichment is optional
  }
}
