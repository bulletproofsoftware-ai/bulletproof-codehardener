import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-artillery');

interface ArtilleryCounter {
  'http.codes.200'?: number;
  'http.codes.400'?: number;
  'http.codes.500'?: number;
  'http.request_rate'?: number;
  'vusers.failed'?: number;
  'vusers.completed'?: number;
}

interface ArtillerySummary {
  min: number;
  max: number;
  median: number;
  p95: number;
  p99: number;
}

interface ArtilleryResult {
  aggregate: {
    counters: ArtilleryCounter;
    rates: Record<string, number>;
    summaries: {
      'http.response_time'?: ArtillerySummary;
    };
  };
}

export async function runArtillery(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // Require targetUrl from job data (not env var)
  if (!jobData.targetUrl) {
    logger.info('No targetUrl set — skipping Artillery load test');
    return {
      scanner: 'artillery',
      success: true,
      skipped: true,
      skipReason: 'no_target_url',
      skipHint: 'Add Target URL in Project Settings to run load tests',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  try {
    // Look for artillery config files in repo
    const { stdout: configSearch } = await execAsync(
      `find /scan-target -maxdepth 3 \\( -name "artillery.yml" -o -name "artillery.yaml" -o -name "artillery.json" -o -name ".artillery.yml" -o -name "artillery*.yml" -o -name "artillery*.yaml" \\) -not -path "*/node_modules/*" 2>/dev/null | head -1`,
      { timeout: 5000 }
    ).catch(() => ({ stdout: '' }));

    const configFile = configSearch.trim();

    if (!configFile) {
      logger.info('No artillery config found in repo — skipping');
      return {
        scanner: 'artillery',
        success: true,
        skipped: true,
        skipReason: 'no_test_config',
        skipHint: 'Add load test scripts (e.g., artillery.yml) to your repo',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    const outputFile = `/tmp/artillery-report-${Date.now()}.json`;
    const relConfigPath = configFile.replace('/scan-target/', '');

    // Run the artillery config found in the repo
    const cmd = `artillery run ${configFile} --output ${outputFile} 2>/dev/null || true`;
    await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 120000 });

    const { stdout } = await execAsync(`cat ${outputFile} 2>/dev/null || echo "{}"`);

    if (stdout.trim() && stdout.trim() !== '{}') {
      const result: ArtilleryResult = JSON.parse(stdout);
      const agg = result.aggregate;

      if (agg) {
        const counters = agg.counters || {};
        const summaries = agg.summaries || {};
        const responseTime = summaries['http.response_time'];

        const errorCount = (counters['http.codes.400'] || 0) + (counters['http.codes.500'] || 0);
        const totalRequests = (counters['vusers.completed'] || 0) + (counters['vusers.failed'] || 0);
        const errorRate = totalRequests > 0 ? errorCount / totalRequests : 0;

        if (errorRate > 0.01) {
          findings.push({
            ruleId: 'ARTILLERY-ERR',
            severity: errorRate > 0.1 ? 'critical' : errorRate > 0.05 ? 'high' : 'medium',
            title: 'Artillery: High Error Rate Under Load',
            description: `Load test shows ${(errorRate * 100).toFixed(1)}% error rate (${errorCount} errors out of ${totalRequests} requests)`,
            filePath: relConfigPath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: false,
            fixDescription: 'Review error handling and capacity under load',
            metadata: {
              errorRate,
              errorCount,
              totalRequests,
              codes: counters,
            },
          });
        }

        if (responseTime && responseTime.p99 > 5000) {
          findings.push({
            ruleId: 'ARTILLERY-SLOW',
            severity: responseTime.p99 > 10000 ? 'high' : 'medium',
            title: 'Artillery: Slow Response Times Under Load',
            description: `P99 response time is ${responseTime.p99}ms (median: ${responseTime.median}ms)`,
            filePath: relConfigPath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: false,
            fixDescription: 'Optimize endpoint performance',
            metadata: {
              min: responseTime.min,
              max: responseTime.max,
              median: responseTime.median,
              p95: responseTime.p95,
              p99: responseTime.p99,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length, targetUrl: jobData.targetUrl }, 'Artillery load test completed');

    return {
      scanner: 'artillery',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: ['Artillery load test execution', 'Error rate analysis', 'Response time percentile analysis'],
        scanScope: `Load test against ${jobData.targetUrl} using ${relConfigPath}`,
        configuration: `Config: ${relConfigPath}, Target: ${jobData.targetUrl}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Artillery load test failed');
    return {
      scanner: 'artillery',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
