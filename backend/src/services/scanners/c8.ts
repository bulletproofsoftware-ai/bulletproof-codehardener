import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-c8');

const SCAN_TARGET = '/scan-target';

interface CoverageSummaryFile {
  lines: { total: number; covered: number; pct: number };
  statements: { total: number; covered: number; pct: number };
  functions: { total: number; covered: number; pct: number };
  branches: { total: number; covered: number; pct: number };
}

interface CoverageSummary {
  total: CoverageSummaryFile;
  [filePath: string]: CoverageSummaryFile;
}

export async function runC8(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for JS/TS project or Python project
    const hasPackageJson = existsSync(`${SCAN_TARGET}/package.json`);
    const { stdout: pyCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );

    if (!hasPackageJson && !pyCheck.trim()) {
      return {
        scanner: 'c8',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package.json or Python files found',
        skipReason: 'no_matching_files',
        skipHint: 'No testable project detected — c8 requires a JavaScript/TypeScript or Python project',
      };
    }

    // Look for existing coverage data (from jest --coverage or c8/nyc runs)
    const coveragePaths = [
      `${SCAN_TARGET}/coverage/coverage-summary.json`,
      `${SCAN_TARGET}/coverage/coverage-final.json`,
      `${SCAN_TARGET}/.nyc_output/coverage-summary.json`,
    ];

    let coverageSummary: CoverageSummary | null = null;

    for (const coveragePath of coveragePaths) {
      if (existsSync(coveragePath)) {
        try {
          const raw = readFileSync(coveragePath, 'utf-8');
          coverageSummary = JSON.parse(raw) as CoverageSummary;
          break;
        } catch {
          // Try next path
        }
      }
    }

    // If no coverage data exists, attempt to generate it for JS/TS projects
    if (!coverageSummary && hasPackageJson) {
      try {
        await execAsync(
          `cd ${SCAN_TARGET} && npx --yes c8 --reporter json-summary --reports-dir /tmp/c8-coverage npx jest --passWithNoTests 2>/dev/null || true`,
          { maxBuffer: 50 * 1024 * 1024, timeout: 180000 }
        );

        const tmpCoveragePath = '/tmp/c8-coverage/coverage-summary.json';
        if (existsSync(tmpCoveragePath)) {
          const raw = readFileSync(tmpCoveragePath, 'utf-8');
          coverageSummary = JSON.parse(raw) as CoverageSummary;
        }
      } catch {
        // Coverage generation failed, will be handled below
      }
    }

    if (!coverageSummary) {
      return {
        scanner: 'c8',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No coverage data available',
        skipReason: 'no_test_config',
        skipHint: 'Run tests with coverage enabled first (e.g., jest --coverage or c8 npx jest)',
      };
    }

    const threshold = (jobData.options as Record<string, unknown>)?.coverageThreshold as number ?? 70;

    // Check per-file coverage
    for (const [filePath, fileCoverage] of Object.entries(coverageSummary)) {
      if (filePath === 'total') continue;

      const linePct = fileCoverage.lines?.pct ?? 0;
      const branchPct = fileCoverage.branches?.pct ?? 0;
      const funcPct = fileCoverage.functions?.pct ?? 0;
      const avgCoverage = (linePct + branchPct + funcPct) / 3;

      if (avgCoverage < threshold) {
        const cleanPath = filePath.replace(`${SCAN_TARGET}/`, '');

        findings.push({
          ruleId: 'COVERAGE-LOW',
          severity: 'medium',
          title: `Low test coverage: ${cleanPath} (${avgCoverage.toFixed(1)}%)`,
          description: `File has ${linePct.toFixed(1)}% line, ${branchPct.toFixed(1)}% branch, and ${funcPct.toFixed(1)}% function coverage. Threshold: ${threshold}%.`,
          filePath: cleanPath,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: 'CWE-1164',
          owaspCategory: null,
          fixAvailable: false,
          fixDescription: `Add tests to increase coverage above ${threshold}%. Focus on uncovered branches and functions.`,
          metadata: {
            lineCoverage: linePct,
            branchCoverage: branchPct,
            functionCoverage: funcPct,
            averageCoverage: avgCoverage,
            threshold,
            linesTotal: fileCoverage.lines?.total ?? 0,
            linesCovered: fileCoverage.lines?.covered ?? 0,
          },
        });
      }
    }

    // Check overall coverage
    const totalCoverage = coverageSummary.total;
    if (totalCoverage) {
      const overallAvg = (
        (totalCoverage.lines?.pct ?? 0) +
        (totalCoverage.branches?.pct ?? 0) +
        (totalCoverage.functions?.pct ?? 0)
      ) / 3;

      if (overallAvg < threshold) {
        findings.unshift({
          ruleId: 'COVERAGE-LOW',
          severity: 'medium',
          title: `Overall test coverage below threshold: ${overallAvg.toFixed(1)}%`,
          description: `Project-wide coverage is ${overallAvg.toFixed(1)}% (lines: ${totalCoverage.lines?.pct ?? 0}%, branches: ${totalCoverage.branches?.pct ?? 0}%, functions: ${totalCoverage.functions?.pct ?? 0}%). Threshold: ${threshold}%.`,
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: 'CWE-1164',
          owaspCategory: null,
          fixAvailable: false,
          fixDescription: `Increase overall test coverage to at least ${threshold}%.`,
          metadata: {
            lineCoverage: totalCoverage.lines?.pct ?? 0,
            branchCoverage: totalCoverage.branches?.pct ?? 0,
            functionCoverage: totalCoverage.functions?.pct ?? 0,
            averageCoverage: overallAvg,
            threshold,
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length }, 'c8 coverage scan completed');

    return {
      scanner: 'c8',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify(coverageSummary.total || {}),
      evidence: {
        checksPerformed: [
          'Line coverage analysis',
          'Branch coverage analysis',
          'Function coverage analysis',
          `Threshold enforcement (${threshold}%)`,
        ],
        scanScope: 'Code coverage analysis via c8/istanbul',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: `Coverage threshold: ${threshold}%`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'c8 coverage scan failed');
    return {
      scanner: 'c8',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
