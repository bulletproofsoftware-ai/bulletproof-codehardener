import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-oxlint');

const SCAN_TARGET = '/scan-target';

interface OxlintDiagnostic {
  ruleId: string;
  severity: string;
  message: string;
  causes?: string[];
  labels?: Array<{ span: { offset: number; length: number }; sourceText?: string }>;
  url?: string;
  filename?: string;
  line?: number;
  column?: number;
}

function mapSeverity(s: string): Severity {
  if (s === 'error') return 'high';
  if (s === 'warning') return 'medium';
  return 'low';
}

export async function runOxlint(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    const { stdout: hasFiles } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 \\( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \\) -not -path "*/node_modules/*" -not -path "*/.next/*" -not -path "*/dist/*" 2>/dev/null | head -1`,
      { timeout: 5000 }
    ).catch(() => ({ stdout: '' }));

    if (!hasFiles.trim()) {
      return { scanner: 'oxlint', success: true, skipped: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No JS/TS files found', skipReason: 'no_matching_files', skipHint: 'No .js/.ts files found — Oxlint requires a JavaScript/TypeScript project' };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && oxlint --format json . 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 60000 }
    );

    if (!stdout.trim()) {
      return { scanner: 'oxlint', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No output' };
    }

    let diagnostics: OxlintDiagnostic[];
    try {
      const parsed = JSON.parse(stdout.trim());
      diagnostics = Array.isArray(parsed) ? parsed : (parsed.diagnostics || parsed.results || []);
    } catch {
      diagnostics = stdout.trim().split('\n').filter(Boolean).map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean) as OxlintDiagnostic[];
    }

    for (const diag of diagnostics.slice(0, 200)) {
      const cleanPath = (diag.filename || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      findings.push({
        ruleId: `OXLINT-${diag.ruleId || 'UNKNOWN'}`,
        severity: mapSeverity(diag.severity),
        title: `${diag.ruleId || 'oxlint'}: ${diag.message}`,
        description: diag.message + (diag.causes?.length ? '\n\n' + diag.causes.join('\n') : ''),
        filePath: cleanPath || null, lineNumber: diag.line || null, columnNumber: diag.column || null,
        codeSnippet: diag.labels?.[0]?.sourceText || null,
        cweId: null, owaspCategory: null, fixAvailable: false, fixDescription: null,
        metadata: { ruleId: diag.ruleId, url: diag.url },
      });
    }

    logger.info({ findingsCount: findings.length }, 'Oxlint scan completed');
    return {
      scanner: 'oxlint', success: true, findings, duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        checksPerformed: ['JavaScript/TypeScript linting', 'Code correctness checks', 'Performance anti-patterns', 'Suspicious code detection'],
        scanScope: 'JS/TS source files',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Oxlint scan failed');
    return { scanner: 'oxlint', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
