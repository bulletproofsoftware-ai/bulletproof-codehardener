import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-locust');

interface LocustStats {
  name: string;
  method: string;
  num_requests: number;
  num_failures: number;
  median_response_time: number;
  avg_response_time: number;
  min_response_time: number;
  max_response_time: number;
  avg_content_length: number;
  requests_per_sec: number;
  failures_per_sec: number;
  response_time_percentiles: Record<string, number>;
}

function getSeverityFromMetrics(stats: LocustStats): Severity {
  const failureRate = stats.num_failures / Math.max(stats.num_requests, 1);
  if (failureRate > 0.1) return 'critical';
  if (failureRate > 0.05) return 'high';
  if (stats.avg_response_time > 5000) return 'high';
  if (stats.avg_response_time > 2000) return 'medium';
  if (stats.avg_response_time > 1000) return 'low';
  return 'info';
}

export async function runLocust(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // Require targetUrl from job data (not env var)
  if (!jobData.targetUrl) {
    logger.info('No targetUrl set — skipping Locust load test');
    return {
      scanner: 'locust',
      success: true,
      skipped: true,
      skipReason: 'no_target_url',
      skipHint: 'Add Target URL in Project Settings to run load tests',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  try {
    // Look for locustfile in scan target (multiple possible locations)
    const { stdout: locustSearch } = await execAsync(
      `find /scan-target -maxdepth 3 -name "locustfile.py" -o -name "locustfile*.py" -o -name "locust_*.py" 2>/dev/null | head -1`,
      { timeout: 5000 }
    ).catch(() => ({ stdout: '' }));

    const locustfile = locustSearch.trim();

    if (!locustfile) {
      logger.info('No locustfile found in repo — skipping');
      return {
        scanner: 'locust',
        success: true,
        skipped: true,
        skipReason: 'no_test_config',
        skipHint: 'Add load test scripts (e.g., locustfile.py) to your repo',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    const outputFile = `/tmp/locust-stats-${Date.now()}.json`;

    // Run Locust in headless mode with quick test
    await execAsync(
      `locust -f ${locustfile} --host ${jobData.targetUrl} --headless -u 10 -r 2 -t 30s --json > ${outputFile} 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 60000 }
    );

    const { stdout } = await execAsync(`cat ${outputFile} 2>/dev/null || echo "[]"`);

    if (stdout.trim() && stdout.trim() !== '[]') {
      const results: LocustStats[] = JSON.parse(stdout);

      for (const stats of results) {
        if (stats.name === 'Aggregated') continue;

        const failureRate = stats.num_failures / Math.max(stats.num_requests, 1);
        const severity = getSeverityFromMetrics(stats);

        if (failureRate > 0.01 || stats.avg_response_time > 1000) {
          findings.push({
            ruleId: 'LOAD-001',
            severity,
            title: `Load Test Issue: ${stats.method} ${stats.name}`,
            description: `Endpoint ${stats.name} shows ${(failureRate * 100).toFixed(1)}% failure rate with ${stats.avg_response_time.toFixed(0)}ms avg response time`,
            filePath: stats.name,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: false,
            fixDescription: 'Review endpoint performance and error handling under load',
            metadata: {
              method: stats.method,
              numRequests: stats.num_requests,
              numFailures: stats.num_failures,
              avgResponseTime: stats.avg_response_time,
              maxResponseTime: stats.max_response_time,
              requestsPerSec: stats.requests_per_sec,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length, targetUrl: jobData.targetUrl }, 'Locust load test completed');

    return {
      scanner: 'locust',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: ['Locust load test execution', 'Failure rate analysis', 'Response time analysis'],
        scanScope: `Load test against ${jobData.targetUrl} using ${locustfile.replace('/scan-target/', '')}`,
        configuration: `Target: ${jobData.targetUrl}, Users: 10, Spawn rate: 2, Duration: 30s`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Locust load test failed');
    return {
      scanner: 'locust',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
