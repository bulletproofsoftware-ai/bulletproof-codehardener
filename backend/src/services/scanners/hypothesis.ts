import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-hypothesis');

const SCAN_TARGET = '/scan-target';

export async function runHypothesis(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for Python files
    const { stdout: pyCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );

    if (!pyCheck.trim()) {
      return {
        scanner: 'hypothesis',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Python files found',
        skipReason: 'no_matching_files',
        skipHint: 'No .py files found — Hypothesis requires a Python project',
      };
    }

    // Check for hypothesis in requirements
    const { stdout: reqCheck } = await execAsync(
      `cat ${SCAN_TARGET}/requirements*.txt ${SCAN_TARGET}/setup.py ${SCAN_TARGET}/pyproject.toml 2>/dev/null | grep -i hypothesis || true`,
      { timeout: 10000 }
    );

    if (!reqCheck.trim()) {
      return {
        scanner: 'hypothesis',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No hypothesis dependency found in requirements',
        skipReason: 'no_property_tests',
        skipHint: 'Add hypothesis to your Python dependencies to enable property-based testing',
      };
    }

    // Run pytest targeting hypothesis tests
    const cmd = `cd ${SCAN_TARGET} && python3 -m pytest -x --tb=short -q 2>/dev/null || true`;
    const { stdout, stderr } = await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 180000,
    });

    const output = stdout + '\n' + stderr;

    // Parse pytest output for failures
    // Hypothesis failures include "Falsifying example:" in their output
    const failureBlocks = output.split(/^FAILED /m).slice(1);

    for (const block of failureBlocks) {
      const lines = block.split('\n');
      const testIdLine = lines[0]?.trim() || '';

      // Extract test file and name from pytest ID (e.g., tests/test_foo.py::test_bar)
      const testMatch = testIdLine.match(/^(.+?\.py)::(.+?)(?:\s|$)/);
      const filePath = testMatch?.[1]?.replace(`${SCAN_TARGET}/`, '') ?? null;
      const testName = testMatch?.[2] ?? testIdLine.slice(0, 80);

      // Check if this is a Hypothesis failure (look for counterexample)
      const isHypothesisFailure = output.includes('Falsifying example:') || output.includes('hypothesis');
      const falsifyMatch = block.match(/Falsifying example:\s*(.+?)(?:\n|$)/);
      const counterexample = falsifyMatch?.[1]?.trim() ?? null;

      const snippet = block.slice(0, 2000);

      findings.push({
        ruleId: 'HYPOTHESIS-COUNTEREXAMPLE',
        severity: 'high',
        title: `Property test failure: ${testName.slice(0, 80)}`,
        description: `Hypothesis found a falsifying example that violates a property invariant.${counterexample ? ` Counterexample: ${counterexample}` : ''}`,
        filePath,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: snippet,
        cweId: 'CWE-20',
        owaspCategory: null,
        fixAvailable: false,
        fixDescription: 'Investigate the falsifying example and fix the code to satisfy the property under test.',
        metadata: {
          testName,
          counterexample,
          isHypothesisSpecific: isHypothesisFailure,
        },
      });
    }

    // Also parse short summary line for counts
    const summaryMatch = output.match(/(\d+) failed/);
    const passedMatch = output.match(/(\d+) passed/);

    logger.info(
      {
        findingsCount: findings.length,
        failed: summaryMatch?.[1] ?? 0,
        passed: passedMatch?.[1] ?? 0,
      },
      'Hypothesis scan completed'
    );

    return {
      scanner: 'hypothesis',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: output,
      evidence: {
        checksPerformed: [
          'Property-based test execution via Hypothesis',
          'Falsifying example detection',
          'Invariant violation analysis',
        ],
        scanScope: 'Property-based testing via Python Hypothesis/pytest',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'pytest with Hypothesis integration',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Hypothesis scan failed');
    return {
      scanner: 'hypothesis',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
