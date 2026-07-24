import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-playwright');

interface PlaywrightTestResult {
  config: any;
  suites: PlaywrightSuite[];
  errors: PlaywrightError[];
  stats: {
    startTime: string;
    duration: number;
    expected: number;
    unexpected: number;
    flaky: number;
    skipped: number;
  };
}

interface PlaywrightSuite {
  title: string;
  file: string;
  specs: PlaywrightSpec[];
}

interface PlaywrightSpec {
  title: string;
  ok: boolean;
  tests: Array<{
    title: string;
    status: string;
    duration: number;
    errors: PlaywrightError[];
  }>;
}

interface PlaywrightError {
  message: string;
  stack?: string;
  location?: {
    file: string;
    line: number;
    column: number;
  };
}

export async function runPlaywright(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for playwright config file
    const { stdout: configCheck } = await execAsync(
      `test -f /scan-target/playwright.config.ts -o -f /scan-target/playwright.config.js && echo "exists" || echo "missing"`
    );
    const hasConfig = configCheck.trim() === 'exists';

    // Check for Playwright test files
    const { stdout: testCheck } = await execAsync(
      `find /scan-target -name "*.spec.ts" -o -name "*.spec.js" -o -name "*.test.ts" | head -5 2>/dev/null`
    );
    const hasTests = !!testCheck.trim();

    const targetUrl = jobData.targetUrl;

    // Skip if no config, no tests, and no targetUrl for smoke tests
    if (!hasConfig && !hasTests && !targetUrl) {
      logger.info('No Playwright config, test files, or target URL found');
      return {
        scanner: 'playwright',
        success: true,
        skipped: true,
        skipReason: 'no_test_config',
        skipHint: 'Add a playwright.config.ts or set Application URL for smoke tests',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    // If we have a targetUrl but no config/tests, run smoke tests
    if (!hasConfig && !hasTests && targetUrl) {
      return await runSmokeTests(targetUrl, startTime);
    }

    const outputFile = `/tmp/playwright-results-${Date.now()}.json`;

    // Run Playwright tests with JSON reporter
    const { stdout, stderr } = await execAsync(
      `cd /scan-target && npx playwright test --reporter=json 2>&1 | tee ${outputFile} || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
    );

    // Try to parse JSON results
    try {
      const { stdout: jsonOutput } = await execAsync(`cat ${outputFile} 2>/dev/null || echo "{}"`);

      if (jsonOutput.trim() && jsonOutput.trim() !== '{}') {
        const result: PlaywrightTestResult = JSON.parse(jsonOutput);

        // Check for failed tests
        for (const suite of result.suites || []) {
          for (const spec of suite.specs || []) {
            for (const test of spec.tests || []) {
              if (test.status === 'failed' || test.status === 'timedOut') {
                const severity: Severity = test.status === 'timedOut' ? 'medium' : 'high';

                findings.push({
                  ruleId: 'PLAYWRIGHT-FAIL',
                  severity,
                  title: `Playwright: ${test.status === 'timedOut' ? 'Test Timeout' : 'Test Failed'} - ${test.title}`,
                  description: test.errors?.[0]?.message || `Test "${spec.title} > ${test.title}" ${test.status}`,
                  filePath: suite.file?.replace('/scan-target/', '') || '',
                  lineNumber: test.errors?.[0]?.location?.line || null,
                  columnNumber: test.errors?.[0]?.location?.column || null,
                  codeSnippet: null,
                  cweId: null,
                  owaspCategory: 'A04:2021-Insecure Design',
                  fixAvailable: false,
                  fixDescription: 'Review and fix the failing browser test',
                  metadata: {
                    suite: suite.title,
                    spec: spec.title,
                    status: test.status,
                    duration: test.duration,
                  },
                });
              }
            }
          }
        }

        // Check for high flakiness
        const stats = result.stats;
        if (stats && stats.flaky > 0) {
          const flakyRate = stats.flaky / (stats.expected + stats.unexpected + stats.flaky);
          if (flakyRate > 0.1) {
            findings.push({
              ruleId: 'PLAYWRIGHT-FLAKY',
              severity: 'low',
              title: 'Playwright: High Test Flakiness',
              description: `${stats.flaky} tests are flaky (${(flakyRate * 100).toFixed(1)}% flaky rate)`,
              filePath: null,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A04:2021-Insecure Design',
              fixAvailable: false,
              fixDescription: 'Investigate and fix flaky tests for reliable CI/CD',
              metadata: {
                expected: stats.expected,
                unexpected: stats.unexpected,
                flaky: stats.flaky,
                skipped: stats.skipped,
              },
            });
          }
        }
      }
    } catch {
      // If JSON parsing fails, check for error patterns in raw output
      if (stderr.includes('Error') || stdout.includes('FAILED')) {
        findings.push({
          ruleId: 'PLAYWRIGHT-ERROR',
          severity: 'medium',
          title: 'Playwright: Test Execution Errors',
          description: 'Playwright tests encountered errors during execution',
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A04:2021-Insecure Design',
          fixAvailable: false,
          fixDescription: 'Review test configuration and fix errors',
          metadata: {
            errorSample: stderr.substring(0, 500),
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length }, 'Playwright browser tests completed');

    return {
      scanner: 'playwright',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
    };
  } catch (error) {
    logger.error({ error }, 'Playwright browser tests failed');
    return {
      scanner: 'playwright',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Run smoke tests against a targetUrl when no Playwright config/tests exist.
 * Checks: page loads (HTTP 2xx), console errors, basic security headers.
 */
async function runSmokeTests(targetUrl: string, startTime: number): Promise<ScannerResult> {
  const findings: NormalizedFinding[] = [];

  try {
    // Use playwright to load the page and capture console errors
    const smokeScript = `
      const { chromium } = require('playwright');
      (async () => {
        const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
        const page = await browser.newPage();
        const consoleErrors = [];
        page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
        let response;
        try {
          response = await page.goto('${targetUrl}', { waitUntil: 'networkidle', timeout: 30000 });
        } catch (e) {
          console.log(JSON.stringify({ error: e.message, consoleErrors }));
          await browser.close();
          return;
        }
        const status = response ? response.status() : 0;
        const headers = response ? response.headers() : {};
        console.log(JSON.stringify({ status, headers, consoleErrors, title: await page.title() }));
        await browser.close();
      })();
    `;

    const { stdout } = await execAsync(
      `node -e ${JSON.stringify(smokeScript)} 2>/dev/null || echo '{}'`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 60000 }
    );

    const result = JSON.parse(stdout.trim() || '{}');

    if (result.error) {
      findings.push({
        ruleId: 'PLAYWRIGHT-SMOKE-LOAD',
        severity: 'high',
        title: 'Playwright Smoke: Page Failed to Load',
        description: `Could not load ${targetUrl}: ${result.error}`,
        filePath: targetUrl,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: false,
        fixDescription: 'Ensure the application URL is reachable and returns a valid response',
        metadata: { targetUrl, error: result.error },
      });
    } else {
      // Check HTTP status
      if (result.status && result.status >= 400) {
        findings.push({
          ruleId: 'PLAYWRIGHT-SMOKE-STATUS',
          severity: result.status >= 500 ? 'high' : 'medium',
          title: `Playwright Smoke: HTTP ${result.status}`,
          description: `${targetUrl} returned HTTP ${result.status}`,
          filePath: targetUrl,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: false,
          fixDescription: 'Investigate the HTTP error status returned by the application',
          metadata: { targetUrl, status: result.status },
        });
      }

      // Check console errors
      if (result.consoleErrors && result.consoleErrors.length > 0) {
        findings.push({
          ruleId: 'PLAYWRIGHT-SMOKE-CONSOLE',
          severity: 'low',
          title: `Playwright Smoke: ${result.consoleErrors.length} Console Error(s)`,
          description: `Browser console errors detected on ${targetUrl}`,
          filePath: targetUrl,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: false,
          fixDescription: 'Review and fix browser console errors',
          metadata: {
            targetUrl,
            consoleErrors: result.consoleErrors.slice(0, 10),
            totalErrors: result.consoleErrors.length,
          },
        });
      }

      // Check security headers
      const headers = result.headers || {};
      const missingHeaders: string[] = [];
      if (!headers['x-frame-options'] && !headers['content-security-policy']) missingHeaders.push('X-Frame-Options / CSP frame-ancestors');
      if (!headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
      if (!headers['strict-transport-security']) missingHeaders.push('Strict-Transport-Security');

      if (missingHeaders.length > 0) {
        findings.push({
          ruleId: 'PLAYWRIGHT-SMOKE-HEADERS',
          severity: 'medium',
          title: 'Playwright Smoke: Missing Security Headers',
          description: `Missing security headers on ${targetUrl}: ${missingHeaders.join(', ')}`,
          filePath: targetUrl,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A05:2021-Security Misconfiguration',
          fixAvailable: true,
          fixDescription: `Add missing security headers: ${missingHeaders.join(', ')}`,
          metadata: { targetUrl, missingHeaders },
        });
      }
    }

    logger.info({ findingsCount: findings.length, targetUrl }, 'Playwright smoke tests completed');

    return {
      scanner: 'playwright',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
    };
  } catch (error) {
    logger.error({ error, targetUrl }, 'Playwright smoke tests failed');
    return {
      scanner: 'playwright',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
