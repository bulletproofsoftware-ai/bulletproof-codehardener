import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-actionlint');

const SCAN_TARGET = '/scan-target';

interface ActionlintError {
  message: string;
  filepath: string;
  line: number;
  column: number;
  kind: string;
  snippet: string;
}

function kindToSeverity(kind: string): Severity {
  if (kind === 'security' || kind === 'permissions') return 'high';
  if (kind === 'syntax' || kind === 'type') return 'medium';
  return 'low';
}

export async function runActionlint(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!existsSync(`${SCAN_TARGET}/.github/workflows`)) {
      return { scanner: 'actionlint', success: true, skipped: true, skipReason: 'no_matching_files', skipHint: 'No .github/workflows directory found — actionlint requires GitHub Actions workflow files', findings: [], duration: Date.now() - startTime, rawOutput: 'No .github/workflows directory found' };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && actionlint -format '{{json .}}' 2>/dev/null || true`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
    );

    if (!stdout.trim() || stdout.trim() === 'null' || stdout.trim() === '[]') {
      return { scanner: 'actionlint', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No issues found' };
    }

    let errors: ActionlintError[];
    try {
      const parsed = JSON.parse(stdout.trim());
      errors = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      errors = stdout.trim().split('\n').filter(Boolean).map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean) as ActionlintError[];
    }

    if (stdout.trim() && errors.length === 0) {
      logger.warn('actionlint produced output but no findings could be parsed');
      return {
        scanner: 'actionlint',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'actionlint produced non-empty output but JSON parsing yielded no findings',
        rawOutput: stdout.slice(0, 5000),
      };
    }

    for (const err of errors.slice(0, 100)) {
      const cleanPath = (err.filepath || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      findings.push({
        ruleId: `ACTIONLINT-${(err.kind || 'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
        severity: kindToSeverity(err.kind),
        title: `GitHub Actions: ${err.message}`,
        description: `${err.message}${err.snippet ? `\n\nCode:\n${err.snippet}` : ''}`,
        filePath: cleanPath || null, lineNumber: err.line || null, columnNumber: err.column || null,
        codeSnippet: err.snippet || null, cweId: null, owaspCategory: null,
        fixAvailable: true, fixDescription: `Fix the ${err.kind || 'workflow'} issue in the GitHub Actions workflow file.`,
        metadata: { kind: err.kind },
      });
    }

    logger.info({ findingsCount: findings.length }, 'actionlint scan completed');
    return {
      scanner: 'actionlint', success: true, findings, duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        checksPerformed: ['GitHub Actions workflow syntax validation', 'Action version pinning checks', 'Shell script validation', 'Expression type checking', 'Permissions analysis'],
        scanScope: '.github/workflows/*.yml files',
      },
    };
  } catch (error) {
    logger.error({ error }, 'actionlint scan failed');
    return { scanner: 'actionlint', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
