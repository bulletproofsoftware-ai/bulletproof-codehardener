import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-ruff');

const SCAN_TARGET = '/scan-target';

interface RuffDiagnostic {
  code: string;
  message: string;
  filename: string;
  location: { row: number; column: number };
  end_location: { row: number; column: number };
  url: string | null;
  fix: { message: string; applicability: string } | null;
  noqa_row: number | null;
}

function mapSeverity(code: string): Severity {
  if (!code) return 'info';
  const prefix = code.charAt(0).toUpperCase();
  // S (flake8-bandit) and SEC rules are security-related
  if (prefix === 'S' || code.startsWith('SEC')) return 'high';
  // E (errors) and F (pyflakes) are correctness issues
  if (prefix === 'E' || prefix === 'F') return 'medium';
  // W (warnings) are style/minor issues
  if (prefix === 'W') return 'low';
  // Everything else (C, I, N, D, UP, B, etc.) is informational
  return 'info';
}

export async function runRuff(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Verify Python source files exist before running ruff linter
    const { stdout: pyFileCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );

    if (!pyFileCheck.trim()) {
      return {
        scanner: 'ruff',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Python files found in project',
        skipReason: 'no_matching_files',
        skipHint: 'No .py files found — Ruff requires a Python project',
      };
    }

    // Run ruff with JSON output
    const configFlag = existsSync('/configs/ruff.toml') ? '--config /configs/ruff.toml' : '';
    const cmd = `cd ${SCAN_TARGET} && ruff check --output-format json ${configFlag} . 2>/dev/null || true`;
    const { stdout } = await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024 });

    if (stdout.trim()) {
      const diagnostics: RuffDiagnostic[] = JSON.parse(stdout);

      for (const diag of diagnostics.slice(0, 200)) {
        const ruleId = `RUFF-${diag.code}`;
        const severity = mapSeverity(diag.code);

        findings.push({
          ruleId,
          severity,
          title: `Ruff ${diag.code}: ${diag.message.slice(0, 80)}`,
          description: diag.message,
          filePath: diag.filename.replace(`${SCAN_TARGET}/`, ''),
          lineNumber: diag.location?.row ?? null,
          columnNumber: diag.location?.column ?? null,
          codeSnippet: null,
          cweId: severity === 'high' ? 'CWE-710' : null,
          owaspCategory: null,
          fixAvailable: !!diag.fix,
          fixDescription: diag.fix
            ? `Auto-fix available: ${diag.fix.message} (applicability: ${diag.fix.applicability})`
            : diag.url
              ? `See: ${diag.url}`
              : null,
          metadata: {
            code: diag.code,
            url: diag.url,
            fixApplicability: diag.fix?.applicability ?? null,
            endLocation: diag.end_location ?? null,
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length }, 'Ruff scan completed');

    return {
      scanner: 'ruff',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Pyflakes error detection', 'pycodestyle enforcement',
          'flake8-bandit security checks', 'isort import ordering',
          'pep8-naming conventions', 'pyupgrade modernization',
          'flake8-bugbear bug detection', 'flake8-comprehensions optimization',
        ],
        scanScope: `Python linting and security analysis via Ruff`,
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: existsSync('/configs/ruff.toml')
          ? 'Custom ruff.toml'
          : 'Default Ruff rules',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Ruff scan failed');
    return {
      scanner: 'ruff',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
