import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync } from 'fs';
// fast-check: Property-based testing for JS/TS — generates random inputs to find edge cases
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-fast-check');

const SCAN_TARGET = '/scan-target';

interface JestResult {
  numFailedTestSuites: number;
  numPassedTestSuites: number;
  numTotalTestSuites: number;
  numFailedTests: number;
  numPassedTests: number;
  numTotalTests: number;
  testResults: JestTestSuite[];
}

interface JestTestSuite {
  name: string;
  status: string;
  message: string;
  assertionResults: JestAssertion[];
}

interface JestAssertion {
  ancestorTitles: string[];
  title: string;
  status: string;
  failureMessages: string[];
  fullName: string;
}

export async function runFastCheck(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for package.json
    if (!existsSync(`${SCAN_TARGET}/package.json`)) {
      return {
        scanner: 'fast-check',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package.json found',
        skipReason: 'no_matching_files',
        skipHint: 'No JavaScript/TypeScript project detected — fast-check requires a Node.js project',
      };
    }

    // Check for fast-check dependency or property test files
    let hasFastCheck = false;
    try {
      const pkg = JSON.parse(readFileSync(`${SCAN_TARGET}/package.json`, 'utf-8'));
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };
      hasFastCheck = 'fast-check' in allDeps;
    } catch {
      // Package.json parse failed
    }

    if (!hasFastCheck) {
      // Check for property test files
      const { stdout: propFiles } = await execAsync(
        `find ${SCAN_TARGET} -maxdepth 4 \\( -name "*.property.test.*" -o -name "*.prop.test.*" -o -name "*.property.spec.*" \\) -not -path "*/node_modules/*" 2>/dev/null | head -1`,
        { timeout: 10000 }
      );

      if (!propFiles.trim()) {
        return {
          scanner: 'fast-check',
          success: true,
          skipped: true,
          findings: [],
          duration: Date.now() - startTime,
          rawOutput: 'No fast-check dependency or property test files found',
          skipReason: 'no_property_tests',
          skipHint: 'Install fast-check and add property-based test files (*.property.test.ts)',
        };
      }
    }

    // Run Jest with property test path pattern
    const cmd = `cd ${SCAN_TARGET} && npx --yes jest --testPathPattern="property|prop" --json --outputFile=/tmp/fc-results.json 2>/dev/null || true`;
    await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 180000 });

    // Parse results
    if (existsSync('/tmp/fc-results.json')) {
      const raw = readFileSync('/tmp/fc-results.json', 'utf-8');
      const results: JestResult = JSON.parse(raw);

      for (const suite of results.testResults) {
        for (const assertion of suite.assertionResults) {
          if (assertion.status === 'failed') {
            const testFile = suite.name.replace(`${SCAN_TARGET}/`, '');
            const failureMsg = assertion.failureMessages.join('\n').slice(0, 2000);

            // Extract counterexample from fast-check failure message if present
            const counterexampleMatch = failureMsg.match(/Counterexample:\s*(.+)/);
            const counterexample = counterexampleMatch?.[1] ?? null;

            findings.push({
              ruleId: 'FASTCHECK-COUNTEREXAMPLE',
              severity: 'high',
              title: `Property test failure: ${assertion.fullName.slice(0, 80)}`,
              description: `Property-based test found a counterexample that violates an invariant.${counterexample ? ` Counterexample: ${counterexample}` : ''}`,
              filePath: testFile,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: failureMsg,
              cweId: 'CWE-20',
              owaspCategory: null,
              fixAvailable: false,
              fixDescription: 'Investigate the counterexample and fix the underlying code to satisfy the property.',
              metadata: {
                testName: assertion.fullName,
                ancestorTitles: assertion.ancestorTitles,
                counterexample,
                suiteStatus: suite.status,
              },
            });
          }
        }
      }

      // Report summary even with no failures (for evidence)
      logger.info(
        {
          findingsCount: findings.length,
          totalTests: results.numTotalTests,
          passed: results.numPassedTests,
          failed: results.numFailedTests,
        },
        'fast-check scan completed'
      );
    }

    return {
      scanner: 'fast-check',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: existsSync('/tmp/fc-results.json')
        ? readFileSync('/tmp/fc-results.json', 'utf-8')
        : 'No test output generated',
      evidence: {
        checksPerformed: [
          'Property-based test execution',
          'Counterexample detection',
          'Invariant violation analysis',
        ],
        scanScope: 'Property-based testing via fast-check/Jest',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'Jest with property/prop test path pattern',
      },
    };
  } catch (error) {
    logger.error({ error }, 'fast-check scan failed');
    return {
      scanner: 'fast-check',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
