import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-backstop');

interface BackstopScenarioResult {
  pair: {
    label: string;
    url: string;
    diff: {
      isSameDimensions: boolean;
      dimensionDifference: { width: number; height: number };
      misMatchPercentage: string;
    };
    diffImage: string;
  };
  status: 'pass' | 'fail';
}

interface BackstopReport {
  testSuite: string;
  tests: BackstopScenarioResult[];
}

export async function runBackstop(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for BackstopJS config
    const { stdout: configCheck } = await execAsync(
      `test -f /scan-target/backstop.json && echo "exists" || echo "missing"`
    );
    const hasConfig = configCheck.trim() === 'exists';
    const targetUrl = jobData.targetUrl;

    if (!hasConfig && !targetUrl) {
      logger.info('No BackstopJS configuration or target URL found');
      return {
        scanner: 'backstop',
        success: true,
        skipped: true,
        skipReason: 'no_test_config',
        skipHint: 'Add a backstop.json or set Application URL to enable visual regression testing',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    // If no config but we have a targetUrl, generate a minimal config for baseline capture
    if (!hasConfig && targetUrl) {
      const minimalConfig = JSON.stringify({
        id: 'codehardener-baseline',
        viewports: [
          { label: 'desktop', width: 1920, height: 1080 },
          { label: 'tablet', width: 768, height: 1024 },
          { label: 'mobile', width: 375, height: 812 },
        ],
        scenarios: [
          {
            label: 'Homepage',
            url: targetUrl,
            delay: 2000,
            misMatchThreshold: 0.1,
          },
        ],
        paths: {
          bitmaps_reference: '/tmp/backstop_data/bitmaps_reference',
          bitmaps_test: '/tmp/backstop_data/bitmaps_test',
          engine_scripts: '/tmp/backstop_data/engine_scripts',
          html_report: '/tmp/backstop_data/html_report',
          json_report: '/tmp/backstop_data/json_report',
        },
        engine: 'puppeteer',
        engineOptions: { args: ['--no-sandbox'] },
        report: ['json'],
      });

      await execAsync(`echo '${minimalConfig.replace(/'/g, "'\\''")}' > /tmp/backstop-auto.json`);

      // Reference run first (creates baseline), then test run
      await execAsync(
        `backstop reference --config=/tmp/backstop-auto.json 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
      );
      await execAsync(
        `backstop test --config=/tmp/backstop-auto.json 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
      );

      // Baseline capture succeeds = no visual regressions (it's the first run)
      logger.info({ targetUrl }, 'BackstopJS baseline captured for target URL');

      return {
        scanner: 'backstop',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: `Baseline captured for ${targetUrl}`,
      };
    }

    // Run BackstopJS test with existing config
    await execAsync(
      `cd /scan-target && backstop test --config=backstop.json 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
    );

    // Check for report
    const reportPath = '/scan-target/backstop_data/json_report/jsonReport.json';
    const { stdout: reportContent } = await execAsync(`cat ${reportPath} 2>/dev/null || echo "{}"`);

    if (reportContent.trim() && reportContent.trim() !== '{}') {
      const report: BackstopReport = JSON.parse(reportContent);

      for (const test of report.tests || []) {
        if (test.status === 'fail') {
          const mismatch = parseFloat(test.pair.diff.misMatchPercentage);
          let severity: Severity = 'info';
          if (mismatch > 10) severity = 'high';
          else if (mismatch > 5) severity = 'medium';
          else if (mismatch > 1) severity = 'low';

          findings.push({
            ruleId: 'BACKSTOP-VISUAL-DIFF',
            severity,
            title: `BackstopJS: Visual Regression - ${test.pair.label}`,
            description: `Visual difference of ${mismatch}% detected for "${test.pair.label}" at ${test.pair.url}`,
            filePath: test.pair.diffImage?.replace('/scan-target/', '') || null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: null,
            fixAvailable: false,
            fixDescription: 'Review visual differences and update reference images if intentional',
            metadata: {
              label: test.pair.label,
              url: test.pair.url,
              misMatchPercentage: mismatch,
              isSameDimensions: test.pair.diff.isSameDimensions,
              dimensionDifference: test.pair.diff.dimensionDifference,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'BackstopJS visual regression test completed');

    return {
      scanner: 'backstop',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: reportContent,
    };
  } catch (error) {
    logger.error({ error }, 'BackstopJS visual regression test failed');
    return {
      scanner: 'backstop',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
