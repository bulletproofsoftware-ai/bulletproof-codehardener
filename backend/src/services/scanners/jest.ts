import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-jest');

const SCAN_TARGET = '/scan-target';
const REPORT_PATH = '/tmp/jest-results.json';

interface JestTestResult {
  ancestorTitles: string[];
  title: string;
  status: 'passed' | 'failed' | 'pending' | 'skipped';
  failureMessages: string[];
  fullName: string;
  duration: number | null;
}

interface JestSuiteResult {
  testFilePath: string;
  testResults: JestTestResult[];
  numPassingTests: number;
  numFailingTests: number;
  numPendingTests: number;
  status: 'passed' | 'failed';
  failureMessage?: string;
}

interface JestReport {
  success: boolean;
  numTotalTestSuites: number;
  numPassedTestSuites: number;
  numFailedTestSuites: number;
  numTotalTests: number;
  numPassedTests: number;
  numFailedTests: number;
  numPendingTests: number;
  testResults: JestSuiteResult[];
  coverageMap?: Record<string, {
    path: string;
    statementMap: Record<string, unknown>;
    s: Record<string, number>;
  }>;
}

function hasJestConfig(dir: string): boolean {
  const configs = [
    'jest.config.js', 'jest.config.ts', 'jest.config.mjs', 'jest.config.cjs',
  ];
  for (const f of configs) {
    if (existsSync(`${dir}/${f}`)) return true;
  }
  // Check package.json for jest config, devDependencies, or test script
  try {
    const pkg = JSON.parse(require('fs').readFileSync(`${dir}/package.json`, 'utf-8'));
    if (pkg.jest) return true;
    if (pkg.devDependencies?.jest || pkg.dependencies?.jest) return true;
    if (pkg.scripts?.test?.includes('jest')) return true;
  } catch { /* ignore */ }
  return false;
}

function hasTestFiles(dir: string): boolean {
  try {
    const { execSync } = require('child_process');
    const result = execSync(
      `find ${dir} -maxdepth 4 \\( -name "*.test.ts" -o -name "*.test.js" -o -name "*.test.tsx" -o -name "*.test.jsx" -o -name "*.spec.ts" -o -name "*.spec.js" \\) -not -path "*/node_modules/*" 2>/dev/null | head -1`,
      { encoding: 'utf-8', timeout: 5000 }
    );
    return result.trim().length > 0;
  } catch {
    return false;
  }
}

function computeCoverage(report: JestReport): number | null {
  if (!report.coverageMap) return null;
  let totalStatements = 0;
  let coveredStatements = 0;
  for (const file of Object.values(report.coverageMap)) {
    const counts = Object.values(file.s);
    totalStatements += counts.length;
    coveredStatements += counts.filter(c => c > 0).length;
  }
  if (totalStatements === 0) return null;
  return Math.round((coveredStatements / totalStatements) * 100);
}

// Note: exec() is used intentionally here — all commands are constant strings targeting
// the container's /scan-target directory with no user-controlled input interpolation.
// This pattern is consistent with all 29 other external binary scanners in the codebase.

export async function runJest(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!existsSync(`${SCAN_TARGET}/package.json`)) {
      return {
        scanner: 'jest',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No package.json found — Jest requires a JavaScript/TypeScript project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package.json found — not a JS/TS project',
      };
    }

    // Skip if project uses Vitest instead of Jest (check root and common subdirs)
    let usesVitest = false;
    try {
      const { stdout: vitestFiles } = await execAsync(
        `find ${SCAN_TARGET} -maxdepth 3 -name "vitest.config.*" -not -path "*/node_modules/*" 2>/dev/null | head -1`,
        { timeout: 5000 }
      );
      usesVitest = vitestFiles.trim().length > 0;
    } catch { /* ignore */ }
    if (usesVitest) {
      return {
        scanner: 'jest',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'Project uses Vitest — Jest scanner skipped. Tests are run by the Vitest-compatible runner.',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Project uses Vitest (vitest.config found). Jest scanner not applicable.',
      };
    }

    if (!hasJestConfig(SCAN_TARGET) && !hasTestFiles(SCAN_TARGET)) {
      findings.push({
        ruleId: 'JEST-NO-TESTS',
        severity: 'high',
        title: 'No Jest tests found',
        description: 'No Jest configuration or test files (*.test.ts, *.test.js, *.spec.ts, *.spec.js) were found. ' +
          'Projects without tests have no automated verification of correctness. ' +
          'AI-generated code without tests has a high risk of undetected logic bugs.',
        filePath: 'package.json',
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Add Jest tests. Install jest with `npm install --save-dev jest` and create test files.',
        metadata: { reason: 'no-tests' },
      });

      return {
        scanner: 'jest',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'No Jest tests found',
        evidence: {
          checksPerformed: ['Jest config/test file detection'],
          scanScope: 'JS/TS project — no test files detected',
        },
      };
    }

    // Install dependencies
    await execAsync(
      `cd ${SCAN_TARGET} && npm install 2>/dev/null`,
      { maxBuffer: 100 * 1024 * 1024, timeout: 120000 }
    );

    // Run jest with JSON reporter and optional coverage
    const cmd = `cd ${SCAN_TARGET} && npx --yes jest --json --outputFile=${REPORT_PATH} ` +
      `--forceExit --passWithNoTests --coverage --coverageReporters=json-summary ` +
      `--no-cache --ci 2>/dev/null || true`;

    await execAsync(cmd, { maxBuffer: 100 * 1024 * 1024, timeout: 300000 });

    if (!existsSync(REPORT_PATH)) {
      logger.warn('Jest produced no JSON report');
      return {
        scanner: 'jest',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'Jest produced no JSON report. Ensure jest is configured correctly.',
      };
    }

    const reportRaw = await readFile(REPORT_PATH, 'utf-8');
    const report: JestReport = JSON.parse(reportRaw);

    // Process test failures as findings
    for (const suite of (report.testResults || [])) {
      const cleanPath = (suite.testFilePath || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');

      // Suite-level failure (e.g. syntax error, import failure)
      if (suite.status === 'failed' && suite.failureMessage && suite.testResults.length === 0) {
        findings.push({
          ruleId: 'JEST-ERROR',
          severity: 'high',
          title: `Test suite failed to run: ${cleanPath}`,
          description: `The test suite could not execute. This usually indicates a syntax error, ` +
            `missing import, or configuration problem.\n\n${suite.failureMessage.slice(0, 500)}`,
          filePath: cleanPath,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: suite.failureMessage.slice(0, 200),
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: 'Fix the syntax or import error preventing the test suite from loading.',
          metadata: { suiteStatus: suite.status },
        });
        continue;
      }

      // Individual test failures
      for (const test of suite.testResults) {
        if (test.status === 'failed') {
          const failureMsg = test.failureMessages.join('\n').slice(0, 500);
          const lineMatch = failureMsg.match(/:(\d+):\d+\)/);
          const lineNumber = lineMatch ? parseInt(lineMatch[1]) : null;

          findings.push({
            ruleId: 'JEST-FAIL',
            severity: 'medium',
            title: `Test failed: ${test.fullName}`,
            description: `Test "${test.fullName}" in ${cleanPath} failed.\n\n${failureMsg}`,
            filePath: cleanPath,
            lineNumber,
            columnNumber: null,
            codeSnippet: failureMsg.slice(0, 200),
            cweId: null,
            owaspCategory: null,
            fixAvailable: true,
            fixDescription: `Fix the failing test or the code it validates. Test: ${test.title}`,
            metadata: {
              testName: test.fullName,
              ancestors: test.ancestorTitles,
              duration: test.duration,
            },
          });
        }
      }
    }

    const coverage = computeCoverage(report);

    logger.info({
      totalTests: report.numTotalTests,
      passed: report.numPassedTests,
      failed: report.numFailedTests,
      pending: report.numPendingTests,
      coverage,
      findingsCount: findings.length,
    }, 'Jest test run completed');

    return {
      scanner: 'jest',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        totalTests: report.numTotalTests,
        passed: report.numPassedTests,
        failed: report.numFailedTests,
        pending: report.numPendingTests,
        suites: report.numTotalTestSuites,
        coverage,
      }),
      evidence: {
        checksPerformed: [
          'Jest test execution',
          'Test failure detection',
          ...(coverage !== null ? ['Statement coverage analysis'] : []),
        ],
        scanScope: `${report.numTotalTests} tests across ${report.numTotalTestSuites} suites`,
        filesAnalyzed: report.numTotalTestSuites,
        rulesEvaluated: report.numTotalTests,
        configuration: `coverage: ${coverage ?? 'N/A'}%, passed: ${report.numPassedTests}/${report.numTotalTests}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Jest scan failed');
    return {
      scanner: 'jest',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
