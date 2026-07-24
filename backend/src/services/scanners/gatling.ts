/** @deprecated Removed from active scanner rotation in v2. Passive results reader replaced by Artillery + Locust. */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-gatling');

/**
 * Gatling Load Test Results Analyzer
 *
 * Requires jobData.targetUrl AND Gatling simulation/result files in repo.
 * Analyzes:
 * - Performance thresholds exceeded
 * - High error rates under load
 * - Per-endpoint error rates
 */
export async function runGatling(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // Require targetUrl from job data
  if (!jobData.targetUrl) {
    logger.info('No targetUrl set — skipping Gatling analysis');
    return {
      scanner: 'gatling',
      success: true,
      skipped: true,
      skipReason: 'no_target_url',
      skipHint: 'Add Target URL in Project Settings to run load tests',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  try {
    // Look for Gatling results and simulation files
    const { stdout: resultSearch } = await execAsync(
      `find /scan-target \\( ` +
      `-name "simulation.log" -o ` +
      `-name "stats.json" -path "*/gatling/*" -o ` +
      `-name "*.scala" -path "*/simulations/*" -o ` +
      `-name "gatling.conf" ` +
      `\\) -not -path "*/node_modules/*" 2>/dev/null`
    ).catch(() => ({ stdout: '' }));

    const resultFiles = resultSearch.trim().split('\n').filter(Boolean);
    if (resultFiles.length === 0) {
      logger.info('No Gatling results or simulations found');
      return {
        scanner: 'gatling',
        success: true,
        skipped: true,
        skipReason: 'no_test_config',
        skipHint: 'Add Gatling simulation files (e.g., simulations/*.scala, gatling.conf) to your repo',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    for (const resultFile of resultFiles) {
      try {
        const relativePath = resultFile.replace('/scan-target/', '');

        // Handle stats.json (Gatling report output)
        if (resultFile.endsWith('stats.json')) {
          const { stdout: content } = await execAsync(`cat "${resultFile}"`, { maxBuffer: 10 * 1024 * 1024 });
          const stats = JSON.parse(content);

          // Check overall stats
          if (stats.stats) {
            const s = stats.stats;
            const errorRate = s.numberOfRequests?.ko
              ? s.numberOfRequests.ko / (s.numberOfRequests.total || 1)
              : 0;

            if (errorRate > 0.05) {
              findings.push({
                ruleId: 'GATLING-HIGH-ERROR-RATE',
                severity: errorRate > 0.2 ? 'critical' : 'high',
                title: `Gatling: High Error Rate Under Load (${(errorRate * 100).toFixed(1)}%)`,
                description: `${s.numberOfRequests.ko} of ${s.numberOfRequests.total} requests failed. Error rate ${(errorRate * 100).toFixed(1)}% exceeds 5% threshold.`,
                filePath: relativePath,
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: null,
                owaspCategory: 'A04:2021-Insecure Design',
                fixAvailable: false,
                fixDescription: 'Investigate failing endpoints and improve error handling under load',
                metadata: {
                  totalRequests: s.numberOfRequests.total,
                  failedRequests: s.numberOfRequests.ko,
                  errorRate: `${(errorRate * 100).toFixed(1)}%`,
                },
              });
            }

            // Check response times
            const p99 = s.percentiles4?.total;
            if (p99 && p99 > 5000) {
              findings.push({
                ruleId: 'GATLING-SLOW-P99',
                severity: p99 > 10000 ? 'high' : 'medium',
                title: `Gatling: Slow p99 Response Time (${p99}ms)`,
                description: `99th percentile response time is ${p99}ms, exceeding 5s threshold. This impacts user experience under load.`,
                filePath: relativePath,
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: null,
                owaspCategory: 'A04:2021-Insecure Design',
                fixAvailable: false,
                fixDescription: 'Profile slow endpoints and optimize database queries, caching, and async processing',
                metadata: {
                  p50: s.percentiles1?.total,
                  p75: s.percentiles2?.total,
                  p95: s.percentiles3?.total,
                  p99,
                  mean: s.meanResponseTime?.total,
                },
              });
            }
          }

          // Check per-group stats for specific endpoint issues
          if (stats.contents) {
            for (const [groupName, groupData] of Object.entries(stats.contents)) {
              const group = groupData as Record<string, any>;
              if (group.stats) {
                const gErrorRate = group.stats.numberOfRequests?.ko
                  ? group.stats.numberOfRequests.ko / (group.stats.numberOfRequests.total || 1)
                  : 0;

                if (gErrorRate > 0.1) {
                  findings.push({
                    ruleId: 'GATLING-ENDPOINT-ERRORS',
                    severity: 'medium',
                    title: `Gatling: Endpoint "${groupName}" - ${(gErrorRate * 100).toFixed(0)}% Error Rate`,
                    description: `Endpoint "${groupName}" has ${group.stats.numberOfRequests.ko} failures out of ${group.stats.numberOfRequests.total} requests.`,
                    filePath: relativePath,
                    lineNumber: null,
                    columnNumber: null,
                    codeSnippet: null,
                    cweId: null,
                    owaspCategory: 'A04:2021-Insecure Design',
                    fixAvailable: false,
                    fixDescription: `Investigate error responses for "${groupName}" and add rate limiting or circuit breaking`,
                    metadata: {
                      endpoint: groupName,
                      total: group.stats.numberOfRequests.total,
                      failed: group.stats.numberOfRequests.ko,
                    },
                  });
                }
              }
            }
          }
        }

        // Handle simulation.log (raw Gatling log)
        if (resultFile.endsWith('simulation.log')) {
          const { stdout: lineCount } = await execAsync(`wc -l < "${resultFile}"`);
          const lines = parseInt(lineCount.trim()) || 0;

          if (lines > 0) {
            // Sample error lines
            const { stdout: errors } = await execAsync(
              `grep "\\tKO\\t" "${resultFile}" | head -10 2>/dev/null || true`
            );

            const errorLines = errors.trim().split('\n').filter(Boolean);
            if (errorLines.length > 0) {
              findings.push({
                ruleId: 'GATLING-LOG-ERRORS',
                severity: 'info',
                title: `Gatling: ${errorLines.length}+ Errors Found in Simulation Log`,
                description: `Simulation log contains failed requests. First error: ${errorLines[0]?.substring(0, 200)}`,
                filePath: relativePath,
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: null,
                owaspCategory: 'A04:2021-Insecure Design',
                fixAvailable: false,
                fixDescription: 'Review simulation log for error patterns',
                metadata: { totalLines: lines, sampleErrors: errorLines.length },
              });
            }
          }
        }
      } catch {
        logger.warn({ resultFile }, 'Failed to parse Gatling result file');
      }
    }

    logger.info({ findingsCount: findings.length, files: resultFiles.length, targetUrl: jobData.targetUrl }, 'Gatling analysis completed');

    return {
      scanner: 'gatling',
      success: true,
      findings,
      duration: Date.now() - startTime,
      evidence: {
        checksPerformed: ['Gatling result analysis', 'Error rate detection', 'Response time percentile analysis'],
        scanScope: `Gatling analysis of ${resultFiles.length} file(s) for target ${jobData.targetUrl}`,
        filesAnalyzed: resultFiles.length,
        configuration: `Target: ${jobData.targetUrl}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Gatling analysis failed');
    return {
      scanner: 'gatling',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
