import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-mutmut');

const SCAN_TARGET = '/scan-target';

function mutationScoreToSeverity(score: number): Severity {
  if (score < 30) return 'high';
  if (score < 70) return 'medium';
  return 'low';
}

function hasPythonTests(dir: string): boolean {
  try {
    const { execFileSync } = require('child_process');
    // execFile with an argument array — no shell interpolation of `dir`.
    const result = execFileSync(
      'find',
      [
        dir, '-maxdepth', '4',
        '(', '-name', 'test_*.py', '-o', '-name', '*_test.py', '-o', '-name', 'tests.py', ')',
        '-not', '-path', '*/venv/*',
        '-not', '-path', '*/.venv/*',
      ],
      { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return result.split('\n').some((line: string) => line.trim().length > 0);
  } catch {
    return false;
  }
}

function findPythonSourceDir(dir: string): string | null {
  // Look for common source directories
  for (const candidate of ['src', 'lib', 'app', '.']) {
    const fullPath = `${dir}/${candidate}`;
    if (existsSync(fullPath)) {
      try {
        const { execFileSync } = require('child_process');
        // execFile with an argument array — no shell interpolation of `fullPath`.
        const result = execFileSync(
          'find',
          [
            fullPath, '-maxdepth', '2', '-name', '*.py',
            '-not', '-name', 'test_*',
            '-not', '-name', '*_test.py',
            '-not', '-path', '*/test*/*',
            '-not', '-path', '*/venv/*',
          ],
          { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
        );
        if (result.split('\n').some((line: string) => line.trim().length > 0)) {
          return candidate === '.' ? dir : fullPath;
        }
      } catch { continue; }
    }
  }
  return null;
}

export async function runMutmut(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check prerequisites — need Python files and tests
    const hasPyFiles = existsSync(`${SCAN_TARGET}/setup.py`) ||
      existsSync(`${SCAN_TARGET}/pyproject.toml`) ||
      existsSync(`${SCAN_TARGET}/requirements.txt`);

    if (!hasPyFiles) {
      return {
        scanner: 'mutmut',
        success: true,
        skipped: true,
        skipReason: 'no_python_project',
        skipHint: 'No setup.py, pyproject.toml, or requirements.txt found — mutmut requires a Python project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Not a Python project',
      };
    }

    if (!hasPythonTests(SCAN_TARGET)) {
      findings.push({
        ruleId: 'MUTATION-002',
        severity: 'high',
        title: 'No Python test files found for mutation testing',
        description: 'No Python test files (test_*.py, *_test.py) were found. ' +
          'Without tests, mutation testing cannot validate code quality. ' +
          'AI-generated Python code without tests has high risk of undetected logic bugs.',
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Add unit tests using pytest or unittest.',
        metadata: { mutationScore: 0, reason: 'no-tests' },
      });

      return {
        scanner: 'mutmut',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'No Python test files found',
      };
    }

    const sourceDir = findPythonSourceDir(SCAN_TARGET);
    if (!sourceDir) {
      return {
        scanner: 'mutmut',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No Python source directory found to mutate (expected src/, lib/, or .py files at project root)',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Python source files found to mutate',
      };
    }

    // Run mutmut
    const pathsArg = sourceDir === SCAN_TARGET ? '' : `--paths-to-mutate=${sourceDir}`;
    const cmd = `cd ${SCAN_TARGET} && mutmut run ${pathsArg} --no-progress --CI 2>/dev/null; mutmut results 2>/dev/null || true`;

    const { stdout } = await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 300000 });

    // Parse mutmut results output
    // Format: "Survived mutants:\n  file.py line N\n...\nKilled mutants: N\nSurvived: N\n..."
    const lines = stdout.split('\n');

    let killed = 0;
    let survived = 0;
    let suspicious = 0;
    let untested = 0;
    let totalMutants = 0;

    // Parse summary line
    for (const line of lines) {
      const killedMatch = line.match(/killed:\s*(\d+)/i);
      const survivedMatch = line.match(/survived:\s*(\d+)/i);
      const suspiciousMatch = line.match(/suspicious:\s*(\d+)/i);
      const untestedMatch = line.match(/untested:\s*(\d+)/i);
      const totalMatch = line.match(/total:\s*(\d+)/i);

      if (killedMatch) killed = parseInt(killedMatch[1]);
      if (survivedMatch) survived = parseInt(survivedMatch[1]);
      if (suspiciousMatch) suspicious = parseInt(suspiciousMatch[1]);
      if (untestedMatch) untested = parseInt(untestedMatch[1]);
      if (totalMatch) totalMutants = parseInt(totalMatch[1]);
    }

    if (totalMutants === 0) {
      totalMutants = killed + survived + suspicious + untested;
    }

    const overallScore = totalMutants > 0 ? Math.round((killed / totalMutants) * 100) : 0;

    // Parse survived mutant details
    let inSurvivedSection = false;
    const survivedMutants: Array<{ file: string; line: number; id: string }> = [];

    for (const line of lines) {
      if (line.includes('Survived mutants')) {
        inSurvivedSection = true;
        continue;
      }
      if (inSurvivedSection && line.trim()) {
        // Format varies: "--- file.py:42" or "mutant N in file.py line 42"
        const match = line.match(/(?:---\s*)?(\S+\.py):?(\d+)/);
        if (match) {
          survivedMutants.push({
            file: match[1].replace(`${SCAN_TARGET}/`, ''),
            line: parseInt(match[2]),
            id: `mutmut-${survivedMutants.length + 1}`,
          });
        }
      }
      if (inSurvivedSection && !line.trim()) {
        inSurvivedSection = false;
      }
    }

    // Create findings for survived mutants (limit to 20)
    for (const mutant of survivedMutants.slice(0, 20)) {
      findings.push({
        ruleId: 'MUTATION-002',
        severity: mutationScoreToSeverity(overallScore),
        title: `Survived mutant in ${mutant.file}:${mutant.line}`,
        description: `A code mutation at line ${mutant.line} was not caught by any test. ` +
          `Overall mutation score: ${overallScore}% (${killed}/${totalMutants} killed). ` +
          `This indicates weak test assertions around this code path.`,
        filePath: mutant.file,
        lineNumber: mutant.line,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: `Add a test that validates the logic at line ${mutant.line} of ${mutant.file}.`,
        metadata: {
          mutantId: mutant.id,
          overallMutationScore: overallScore,
          totalKilled: killed,
          totalMutants,
        },
      });
    }

    // Add summary finding if score is low
    if (overallScore < 70 && totalMutants > 0 && survivedMutants.length === 0) {
      findings.push({
        ruleId: 'MUTATION-002',
        severity: mutationScoreToSeverity(overallScore),
        title: `Low mutation score: ${overallScore}% (${killed}/${totalMutants} mutants killed)`,
        description: `The overall mutation score is ${overallScore}%, below the recommended 70% threshold. ` +
          `This means ${survived} code mutations were not detected by the test suite.`,
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: `Killed: ${killed}\nSurvived: ${survived}\nSuspicious: ${suspicious}\nUntested: ${untested}`,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Improve test assertions to catch more logic changes. Focus on boundary conditions and edge cases.',
        metadata: { mutationScore: overallScore, killed, survived, suspicious, untested, totalMutants },
      });
    }

    logger.info({ overallScore, totalMutants, killed, survived, findingsCount: findings.length }, 'mutmut scan completed');

    return {
      scanner: 'mutmut',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Python mutation testing',
          'Test quality validation via mutation score',
          'Survived mutant identification',
        ],
        scanScope: `Mutation analysis of Python source in ${sourceDir}, ${totalMutants} mutants generated`,
        filesAnalyzed: undefined,
        rulesEvaluated: totalMutants,
        configuration: `Mutation score: ${overallScore}%, Source: ${sourceDir}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'mutmut scan failed');
    return {
      scanner: 'mutmut',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
