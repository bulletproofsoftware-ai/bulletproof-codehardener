import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-newman');

interface NewmanAssertion {
  assertion: string;
  skipped: boolean;
  error?: {
    name: string;
    index: number;
    test: string;
    message: string;
    stack: string;
  };
}

interface NewmanExecution {
  item: { name: string };
  assertions: NewmanAssertion[];
  response: {
    code: number;
    status: string;
    responseTime: number;
  };
}

interface NewmanRun {
  stats: {
    assertions: { total: number; pending: number; failed: number };
    requests: { total: number; pending: number; failed: number };
  };
  executions: NewmanExecution[];
  failures: Array<{
    error: { name: string; message: string };
    at: string;
    source: { name: string };
  }>;
}

interface NewmanResult {
  run: NewmanRun;
}

export async function runNewman(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Use pre-detected Postman collection from project context, fall back to filesystem search
    let collectionFile = jobData.detectedSpecs?.postmanCollections?.[0]
      ? `/scan-target/${jobData.detectedSpecs.postmanCollections[0]}`
      : '';

    if (!collectionFile) {
      const { stdout: collectionSearch } = await execAsync(
        `find /scan-target -name "*.postman_collection.json" -o -name "postman_collection.json" 2>/dev/null | head -1`
      );
      collectionFile = collectionSearch.trim();
    }

    if (!collectionFile) {
      logger.info('No Postman collection found');
      return {
        scanner: 'newman',
        success: true,
        skipped: true,
        skipReason: 'no_postman_collection',
        skipHint: 'Add a *.postman_collection.json file to your project, or import your API into Postman and export the collection.',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    const outputFile = `/tmp/newman-report-${Date.now()}.json`;

    // Run Newman
    await execAsync(
      `newman run "${collectionFile}" --reporters json --reporter-json-export ${outputFile} 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
    );

    const { stdout } = await execAsync(`cat ${outputFile} 2>/dev/null || echo "{}"`);

    if (stdout.trim() && stdout.trim() !== '{}') {
      const result: NewmanResult = JSON.parse(stdout);
      const run = result.run;

      // Report failures
      for (const failure of run.failures || []) {
        findings.push({
          ruleId: 'NEWMAN-FAIL',
          severity: 'high',
          title: `Newman: Test Failed - ${failure.source?.name || 'Unknown'}`,
          description: `${failure.error.name}: ${failure.error.message}`,
          filePath: collectionFile.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: false,
          fixDescription: `Fix the failing assertion at: ${failure.at}`,
          metadata: {
            assertionLocation: failure.at,
            sourceName: failure.source?.name,
          },
        });
      }

      // Report high failure rate
      const stats = run.stats;
      if (stats.assertions.failed > 0) {
        const failRate = stats.assertions.failed / stats.assertions.total;
        if (failRate > 0.1) {
          findings.push({
            ruleId: 'NEWMAN-HIGH-FAIL',
            severity: failRate > 0.5 ? 'critical' : 'high',
            title: 'Newman: High Assertion Failure Rate',
            description: `${stats.assertions.failed} of ${stats.assertions.total} assertions failed (${(failRate * 100).toFixed(1)}%)`,
            filePath: collectionFile.replace('/scan-target/', ''),
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A04:2021-Insecure Design',
            fixAvailable: false,
            fixDescription: 'Review and fix failing API tests',
            metadata: {
              totalAssertions: stats.assertions.total,
              failedAssertions: stats.assertions.failed,
              totalRequests: stats.requests.total,
              failedRequests: stats.requests.failed,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'Newman API test completed');

    return {
      scanner: 'newman',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
    };
  } catch (error) {
    logger.error({ error }, 'Newman API test failed');
    return {
      scanner: 'newman',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
