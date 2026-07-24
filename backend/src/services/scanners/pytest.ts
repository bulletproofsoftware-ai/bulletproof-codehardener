import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-pytest');

const SCAN_TARGET = '/scan-target';
const REPORT_PATH = '/tmp/pytest-results.json';

interface PytestResult {
  nodeid: string;
  outcome: 'passed' | 'failed' | 'error' | 'skipped' | 'xfailed' | 'xpassed';
  setup?: { outcome: string; duration: number };
  call?: { outcome: string; duration: number; longrepr?: string; crash?: { path: string; lineno: number; message: string } };
  teardown?: { outcome: string; duration: number };
  duration: number;
}

interface PytestReport {
  created: number;
  duration: number;
  exitcode: number;
  root: string;
  environment: Record<string, string>;
  summary: {
    passed?: number;
    failed?: number;
    error?: number;
    skipped?: number;
    total: number;
  };
  tests: PytestResult[];
  collectors?: { nodeid: string; outcome: string; longrepr?: string }[];
}

function hasPytestConfig(dir: string): boolean {
  // Direct pytest config files
  const directConfigs = ['pytest.ini', 'setup.cfg', 'tox.ini', 'conftest.py'];
  for (const f of directConfigs) {
    if (existsSync(`${dir}/${f}`)) return true;
  }

  // Check pyproject.toml for pytest references
  if (existsSync(`${dir}/pyproject.toml`)) {
    try {
      const content = require('fs').readFileSync(`${dir}/pyproject.toml`, 'utf-8');
      if (content.includes('[tool.pytest') || content.includes('pytest')) return true;
    } catch { /* ignore */ }
  }

  // Check requirements.txt for pytest dependency
  const reqFiles = ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt'];
  for (const f of reqFiles) {
    if (existsSync(`${dir}/${f}`)) {
      try {
        const content = require('fs').readFileSync(`${dir}/${f}`, 'utf-8');
        if (content.split('\n').some((line: string) => line.trim().startsWith('pytest'))) return true;
      } catch { /* ignore */ }
    }
  }

  return false;
}

function hasPythonTestFiles(dir: string): boolean {
  try {
    const { execSync } = require('child_process');
    const result = execSync(
      `find ${dir} -maxdepth 4 \\( -name "test_*.py" -o -name "*_test.py" \\) -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { encoding: 'utf-8', timeout: 5000 }
    );
    return result.trim().length > 0;
  } catch {
    return false;
  }
}

function hasPythonFiles(dir: string): boolean {
  try {
    const { execSync } = require('child_process');
    const result = execSync(
      `find ${dir} -maxdepth 6 -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { encoding: 'utf-8', timeout: 5000 }
    );
    return result.trim().length > 0;
  } catch {
    return false;
  }
}

// Note: exec() is used intentionally here — all commands are constant strings targeting
// the container's /scan-target directory with no user-controlled input interpolation.
// This pattern is consistent with all 29 other external binary scanners in the codebase.

export async function runPytest(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!hasPythonFiles(SCAN_TARGET)) {
      return {
        scanner: 'pytest',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No Python files found — pytest requires a Python project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Python files found — not a Python project',
      };
    }

    if (!hasPytestConfig(SCAN_TARGET) && !hasPythonTestFiles(SCAN_TARGET)) {
      findings.push({
        ruleId: 'PYTEST-NO-TESTS',
        severity: 'high',
        title: 'No pytest tests found',
        description: 'No pytest configuration or test files (test_*.py, *_test.py) were found in this Python project. ' +
          'Projects without tests have no automated verification of correctness. ' +
          'AI-generated code without tests has a high risk of undetected logic bugs.',
        filePath: '.',
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Add pytest tests. Install pytest with `pip install pytest` and create test_*.py files.',
        metadata: { reason: 'no-tests' },
      });

      return {
        scanner: 'pytest',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'No pytest tests found',
        evidence: {
          checksPerformed: ['pytest config/test file detection'],
          scanScope: 'Python project — no test files detected',
        },
      };
    }

    if (existsSync(`${SCAN_TARGET}/requirements.txt`)) {
      await execAsync(
        `cd ${SCAN_TARGET} && pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
      );
    }
    if (existsSync(`${SCAN_TARGET}/pyproject.toml`)) {
      await execAsync(
        `cd ${SCAN_TARGET} && pip3 install -e . --break-system-packages 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
      );
    }

    await execAsync(
      'pip3 install pytest pytest-json-report pytest-cov --break-system-packages 2>/dev/null || true',
      { timeout: 60000 }
    );

    const cmd = `cd ${SCAN_TARGET} && python3 -m pytest ` +
      `--json-report --json-report-file=${REPORT_PATH} ` +
      `--cov=. --cov-report=json:/tmp/pytest-coverage.json ` +
      `--tb=short -q --no-header 2>&1 || true`;

    const { stdout: pytestOutput } = await execAsync(cmd, { maxBuffer: 100 * 1024 * 1024, timeout: 300000 });

    if (!existsSync(REPORT_PATH)) {
      const hint = pytestOutput.trim().split('\n').slice(-10).join('\n');
      logger.warn({ hint }, 'pytest produced no JSON report');
      return {
        scanner: 'pytest',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: `pytest produced no JSON report. Last output:\n${hint}`,
      };
    }

    const reportRaw = await readFile(REPORT_PATH, 'utf-8');
    const report: PytestReport = JSON.parse(reportRaw);

    if (report.collectors) {
      for (const collector of report.collectors) {
        if (collector.outcome === 'failed') {
          const cleanPath = collector.nodeid.replace(`${SCAN_TARGET}/`, '');
          findings.push({
            ruleId: 'PYTEST-ERROR',
            severity: 'high',
            title: `Test collection failed: ${cleanPath}`,
            description: `pytest could not collect tests from ${cleanPath}. ` +
              `This usually indicates a syntax error or import failure.\n\n${(collector.longrepr || '').slice(0, 500)}`,
            filePath: cleanPath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: (collector.longrepr || '').slice(0, 200),
            cweId: null,
            owaspCategory: null,
            fixAvailable: true,
            fixDescription: 'Fix the syntax or import error preventing test collection.',
            metadata: { collectorOutcome: collector.outcome },
          });
        }
      }
    }

    for (const test of report.tests) {
      if (test.outcome === 'failed' || test.outcome === 'error') {
        const parts = test.nodeid.split('::');
        const filePath = parts[0].replace(`${SCAN_TARGET}/`, '');
        const testName = parts.slice(1).join('::') || test.nodeid;
        const crash = test.call?.crash;
        const longrepr = test.call?.longrepr || '';

        findings.push({
          ruleId: test.outcome === 'error' ? 'PYTEST-ERROR' : 'PYTEST-FAIL',
          severity: test.outcome === 'error' ? 'high' : 'medium',
          title: `Test ${test.outcome}: ${testName}`,
          description: `Test "${testName}" in ${filePath} ${test.outcome === 'error' ? 'errored' : 'failed'}.\n\n` +
            `${crash ? `${crash.message} (${crash.path}:${crash.lineno})` : longrepr.slice(0, 500)}`,
          filePath,
          lineNumber: crash?.lineno || null,
          columnNumber: null,
          codeSnippet: (longrepr || crash?.message || '').slice(0, 200),
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Fix the failing test or the code it validates. Test: ${testName}`,
          metadata: {
            testId: test.nodeid,
            outcome: test.outcome,
            duration: test.duration,
          },
        });
      }
    }

    let coverage: number | null = null;
    try {
      if (existsSync('/tmp/pytest-coverage.json')) {
        const covRaw = await readFile('/tmp/pytest-coverage.json', 'utf-8');
        const covData = JSON.parse(covRaw);
        coverage = Math.round(covData.totals?.percent_covered ?? 0);
      }
    } catch { /* coverage is optional */ }

    const summary = report.summary;
    const totalTests = summary.total || 0;
    const passed = summary.passed || 0;
    const failed = summary.failed || 0;
    const errors = summary.error || 0;
    const skipped = summary.skipped || 0;

    logger.info({
      totalTests, passed, failed, errors, skipped, coverage,
      findingsCount: findings.length,
    }, 'pytest test run completed');

    return {
      scanner: 'pytest',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({ totalTests, passed, failed, errors, skipped, coverage }),
      evidence: {
        checksPerformed: [
          'pytest test execution',
          'Test failure detection',
          ...(coverage !== null ? ['Statement coverage analysis'] : []),
        ],
        scanScope: `${totalTests} tests`,
        filesAnalyzed: new Set(report.tests.map(t => t.nodeid.split('::')[0])).size,
        rulesEvaluated: totalTests,
        configuration: `coverage: ${coverage ?? 'N/A'}%, passed: ${passed}/${totalTests}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'pytest scan failed');
    return {
      scanner: 'pytest',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
