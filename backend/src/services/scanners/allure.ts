/** @deprecated Removed from active scanner rotation in v2. Passive report aggregator; replaced by unified test results pipeline. */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-allure');

interface AllureTestCase {
  uid: string;
  name: string;
  fullName: string;
  status: 'passed' | 'failed' | 'broken' | 'skipped' | 'unknown';
  statusDetails?: {
    message?: string;
    trace?: string;
  };
  time: {
    start: number;
    stop: number;
    duration: number;
  };
  flaky: boolean;
  newFailed: boolean;
  newBroken: boolean;
  retriesCount: number;
  severity?: string;
}

interface AllureSummary {
  statistic: {
    failed: number;
    broken: number;
    skipped: number;
    passed: number;
    unknown: number;
    total: number;
  };
  time: {
    start: number;
    stop: number;
    duration: number;
    minDuration: number;
    maxDuration: number;
    sumDuration: number;
  };
}

export async function runAllure(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for Allure results directory
    const { stdout: resultsSearch } = await execAsync(
      `find /scan-target -type d -name "allure-results" 2>/dev/null | head -1`
    );

    const resultsDir = resultsSearch.trim();
    if (!resultsDir) {
      logger.info('No Allure results directory found');
      return {
        scanner: 'allure',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_matching_files',
        skipHint: 'No allure-results/ directory found',
      };
    }

    // Generate Allure report
    const reportDir = `/tmp/allure-report-${Date.now()}`;
    await execAsync(`allure generate "${resultsDir}" -o "${reportDir}" --clean 2>/dev/null || true`, { timeout: 120000 });

    // Read summary
    const summaryPath = `${reportDir}/widgets/summary.json`;
    const { stdout: summaryContent } = await execAsync(`cat "${summaryPath}" 2>/dev/null || echo "{}"`);

    if (summaryContent.trim() && summaryContent.trim() !== '{}') {
      const summary: AllureSummary = JSON.parse(summaryContent);
      const stats = summary.statistic;

      // Report test failures
      if (stats.failed > 0 || stats.broken > 0) {
        const failureCount = stats.failed + stats.broken;
        const failureRate = failureCount / stats.total;

        findings.push({
          ruleId: 'ALLURE-FAILURES',
          severity: failureRate > 0.2 ? 'critical' : failureRate > 0.1 ? 'high' : 'medium',
          title: 'Allure: Test Failures Detected',
          description: `${stats.failed} failed and ${stats.broken} broken tests out of ${stats.total} total (${(failureRate * 100).toFixed(1)}% failure rate)`,
          filePath: resultsDir.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: false,
          fixDescription: 'Review and fix failing tests',
          metadata: {
            failed: stats.failed,
            broken: stats.broken,
            passed: stats.passed,
            skipped: stats.skipped,
            total: stats.total,
            duration: summary.time.duration,
          },
        });
      }
    }

    // Check for flaky tests
    const flakyPath = `${reportDir}/widgets/flaky.json`;
    const { stdout: flakyContent } = await execAsync(`cat "${flakyPath}" 2>/dev/null || echo "[]"`);

    if (flakyContent.trim() && flakyContent.trim() !== '[]') {
      const flakyTests: AllureTestCase[] = JSON.parse(flakyContent);

      if (flakyTests.length > 0) {
        findings.push({
          ruleId: 'ALLURE-FLAKY',
          severity: flakyTests.length > 5 ? 'medium' : 'low',
          title: 'Allure: Flaky Tests Detected',
          description: `${flakyTests.length} flaky tests detected that pass/fail intermittently`,
          filePath: resultsDir.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: false,
          fixDescription: 'Investigate and fix flaky tests for reliable CI/CD',
          metadata: {
            flakyCount: flakyTests.length,
            flakyTests: flakyTests.slice(0, 10).map(t => t.name),
          },
        });
      }
    }

    // Check for slow tests
    const durationPath = `${reportDir}/widgets/duration.json`;
    const { stdout: durationContent } = await execAsync(`cat "${durationPath}" 2>/dev/null || echo "[]"`);

    if (durationContent.trim() && durationContent.trim() !== '[]') {
      const durations = JSON.parse(durationContent);
      const slowTests = durations.filter((d: any) => d.duration > 60000); // > 60 seconds

      if (slowTests.length > 0) {
        findings.push({
          ruleId: 'ALLURE-SLOW',
          severity: 'low',
          title: 'Allure: Slow Tests Detected',
          description: `${slowTests.length} tests take longer than 60 seconds`,
          filePath: resultsDir.replace('/scan-target/', ''),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: false,
          fixDescription: 'Consider optimizing slow tests or marking them for separate execution',
          metadata: {
            slowCount: slowTests.length,
            slowTests: slowTests.slice(0, 5).map((t: any) => ({ name: t.name, duration: t.duration })),
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length }, 'Allure report analysis completed');

    return {
      scanner: 'allure',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: summaryContent,
    };
  } catch (error) {
    logger.error({ error }, 'Allure report analysis failed');
    return {
      scanner: 'allure',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
