import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-stryker');

const SCAN_TARGET = '/scan-target';
const REPORT_DIR = '/tmp/stryker-reports';

interface StrykerMutant {
  id: string;
  mutatorName: string;
  replacement: string;
  fileName: string;
  location: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
  status: 'Killed' | 'Survived' | 'NoCoverage' | 'Timeout' | 'CompileError' | 'RuntimeError';
}

interface StrykerReport {
  schemaVersion: string;
  thresholds: { high: number; low: number; break: number };
  files: Record<string, {
    language: string;
    source: string;
    mutants: StrykerMutant[];
  }>;
}

function mutationScoreToSeverity(score: number): Severity {
  if (score < 30) return 'high';
  if (score < 70) return 'medium';
  return 'low';
}

function hasTestFiles(dir: string): boolean {
  // Quick check for common test file patterns
  try {
    const { execSync } = require('child_process');
    const result = execSync(
      `find ${dir} -maxdepth 4 \\( -name "*.test.ts" -o -name "*.test.js" -o -name "*.spec.ts" -o -name "*.spec.js" \\) -not -path "*/node_modules/*" 2>/dev/null | head -1`,
      { encoding: 'utf-8', timeout: 5000 }
    );
    return result.trim().length > 0;
  } catch {
    return false;
  }
}

export async function runStryker(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const mutationScoreThreshold = jobData.options?.mutationScoreThreshold ?? 20;

  try {
    // Check prerequisites
    if (!existsSync(`${SCAN_TARGET}/package.json`)) {
      return {
        scanner: 'stryker',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No package.json found — Stryker requires a JavaScript/TypeScript project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package.json found — not a JS/TS project',
      };
    }

    // Stryker requires Jest/Mocha/Karma — detect and skip Vitest projects
    let vitestDetected = false;
    try {
      const { stdout: vitestCfg } = await execAsync(
        `find ${SCAN_TARGET} -maxdepth 3 -name "vitest.config.*" -not -path "*/node_modules/*" 2>/dev/null | head -1`,
        { timeout: 5000 }
      );
      vitestDetected = vitestCfg.trim().length > 0;
    } catch { /* vitest detection failed — assume not present */ }
    if (vitestDetected) {
      return {
        scanner: 'stryker',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'Project uses Vitest — Stryker requires Jest, Mocha, or Karma as test runner',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Project uses Vitest (vitest.config found). Stryker supports Jest/Mocha/Karma only.',
      };
    }

    if (!hasTestFiles(SCAN_TARGET)) {
      findings.push({
        ruleId: 'MUTATION-001',
        severity: 'high',
        title: 'No test files found for mutation testing',
        description: 'No test files (*.test.ts, *.test.js, *.spec.ts, *.spec.js) were found in the project. ' +
          'Without tests, mutation testing cannot validate code quality. ' +
          'AI-generated code without tests has a high risk of undetected logic bugs.',
        filePath: 'package.json',
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: 'Add unit tests for your code. Use a testing framework like Jest, Vitest, or Mocha.',
        metadata: { mutationScore: 0, reason: 'no-tests' },
      });

      return {
        scanner: 'stryker',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: 'No test files found',
        evidence: {
          checksPerformed: ['Test file existence check'],
          scanScope: 'JS/TS project — no test files detected',
        },
      };
    }

    // Install stryker and run mutation testing
    await execAsync(
      `cd ${SCAN_TARGET} && npm install 2>/dev/null`,
      { maxBuffer: 100 * 1024 * 1024, timeout: 120000 }
    );

    // Run stryker with JSON reporter
    const cmd = `cd ${SCAN_TARGET} && npx --yes @stryker-mutator/core run ` +
      `--reporters json --jsonReporter.fileName ${REPORT_DIR}/mutation.json ` +
      `--concurrency 2 --tempDirName /tmp/stryker-tmp ` +
      `2>/dev/null || true`;

    await execAsync(cmd, { maxBuffer: 100 * 1024 * 1024, timeout: 300000 });

    // Parse report
    const reportPath = `${REPORT_DIR}/mutation.json`;
    if (!existsSync(reportPath)) {
      logger.warn('Stryker produced no report — likely no stryker config or test framework mismatch');
      return {
        scanner: 'stryker',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'Stryker produced no report. Ensure a stryker.conf.js or supported test framework exists.',
      };
    }

    const reportRaw = await readFile(reportPath, 'utf-8');
    const report: StrykerReport = JSON.parse(reportRaw);

    // Calculate overall stats
    let totalMutants = 0;
    let killed = 0;
    let survived = 0;
    let noCoverage = 0;
    let timeout = 0;

    for (const [filePath, fileData] of Object.entries(report.files || {})) {
      const fileMutants = fileData.mutants || [];
      const fileKilled = fileMutants.filter(m => m.status === 'Killed' || m.status === 'Timeout').length;
      const fileSurvived = fileMutants.filter(m => m.status === 'Survived').length;
      const fileNoCoverage = fileMutants.filter(m => m.status === 'NoCoverage').length;
      const fileTotal = fileMutants.length;

      totalMutants += fileTotal;
      killed += fileKilled;
      survived += fileSurvived;
      noCoverage += fileNoCoverage;
      timeout += fileMutants.filter(m => m.status === 'Timeout').length;

      if (fileTotal === 0) continue;

      const fileScore = Math.round((fileKilled / fileTotal) * 100);
      const cleanPath = filePath.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');

      // Only report files with poor mutation scores
      if (fileScore < 70) {
        // Report up to 5 survived mutants per file as specific findings
        const survivedMutants = fileMutants.filter(m => m.status === 'Survived').slice(0, 5);

        for (const mutant of survivedMutants) {
          findings.push({
            ruleId: 'MUTATION-001',
            severity: mutationScoreToSeverity(fileScore),
            title: `Survived mutant: ${mutant.mutatorName} in ${cleanPath}:${mutant.location.start.line}`,
            description: `A mutation (${mutant.mutatorName}) at line ${mutant.location.start.line} was not caught by any test. ` +
              `This means changing the code logic at this location does not cause any test to fail. ` +
              `Mutation score for this file: ${fileScore}% (${fileKilled}/${fileTotal} mutants killed). ` +
              `AI-generated code often produces tests that achieve high coverage but low mutation scores.`,
            filePath: cleanPath,
            lineNumber: mutant.location.start.line,
            columnNumber: mutant.location.start.column,
            codeSnippet: mutant.replacement ? `Mutator: ${mutant.mutatorName}\nReplacement: ${mutant.replacement}` : null,
            cweId: null,
            owaspCategory: null,
            fixAvailable: true,
            fixDescription: `Add a test that validates the logic at line ${mutant.location.start.line}. ` +
              `The ${mutant.mutatorName} mutator changed the code and no test detected the change.`,
            metadata: {
              mutantId: mutant.id,
              mutatorName: mutant.mutatorName,
              mutantStatus: mutant.status,
              fileMutationScore: fileScore,
              fileKilled: fileKilled,
              fileTotal: fileTotal,
            },
          });
        }
      }
    }

    const overallScore = totalMutants > 0 ? Math.round((killed / totalMutants) * 100) : 0;

    // Emit a warning finding when overall mutation score is below the configurable threshold
    if (overallScore < mutationScoreThreshold && totalMutants > 0) {
      findings.push({
        ruleId: 'MUTATION-THRESHOLD',
        severity: mutationScoreToSeverity(overallScore),
        title: `Mutation score ${overallScore}% is below ${mutationScoreThreshold}% threshold`,
        description: `Overall mutation score is ${overallScore}% (${killed}/${totalMutants} mutants killed). ` +
          `The configured threshold is ${mutationScoreThreshold}%. ` +
          `A low mutation score means tests do not effectively validate code logic — ` +
          `mutations (deliberate code changes) survive without causing test failures. ` +
          `This is common with AI-generated tests that achieve high line coverage but low assertion quality.`,
        filePath: 'package.json',
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: `Improve test assertions to kill more mutants. Target: ${mutationScoreThreshold}%+ mutation score.`,
        metadata: {
          mutationScore: overallScore,
          threshold: mutationScoreThreshold,
          killed,
          survived,
          noCoverage,
          totalMutants,
        },
      });
    }

    logger.info({
      overallScore,
      mutationScoreThreshold,
      totalMutants,
      killed,
      survived,
      noCoverage,
      findingsCount: findings.length,
    }, 'Stryker mutation testing completed');

    return {
      scanner: 'stryker',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        mutationScore: overallScore,
        totalMutants,
        killed,
        survived,
        noCoverage,
        timeout,
      }),
      evidence: {
        checksPerformed: [
          'JavaScript/TypeScript mutation testing',
          'Test quality validation via mutation score',
          'Survived mutant identification',
          'Code coverage gap detection',
          `Mutation score threshold check (${mutationScoreThreshold}%)`,
        ],
        scanScope: `Mutation analysis of ${Object.keys(report.files || {}).length} source files, ${totalMutants} mutants generated`,
        filesAnalyzed: Object.keys(report.files || {}).length,
        rulesEvaluated: totalMutants,
        configuration: `Concurrency: 2, Mutation score: ${overallScore}%, Threshold: ${mutationScoreThreshold}%`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Stryker scan failed');
    return {
      scanner: 'stryker',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
