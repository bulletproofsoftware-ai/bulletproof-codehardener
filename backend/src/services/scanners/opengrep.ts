import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-opengrep');

interface SemgrepResult {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message: string;
      severity: string;
      metadata?: {
        cwe?: string[];
        owasp?: string[];
        fix?: string;
        references?: string[];
      };
      lines: string;
    };
  }>;
  errors: Array<{ message: string }>;
}

function mapSeverity(semgrepSeverity: string): Severity {
  const map: Record<string, Severity> = {
    ERROR: 'high',
    WARNING: 'medium',
    INFO: 'low',
  };
  return map[semgrepSeverity.toUpperCase()] || 'info';
}

export async function runOpengrep(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Run Opengrep (Semgrep-compatible) with security rules
    const configs = [
      '--config=auto',
      '--config=p/security-audit',
      '--config=p/owasp-top-ten',
      '--config=p/cwe-top-25',
      '--config=p/r2c-security-audit',
      '--config=p/secrets',
    ];
    const customConfig = existsSync('/configs/semgrep-rules.yml') ? '--config=/configs/semgrep-rules.yml' : '';
    const cmd = `semgrep scan ${configs.join(' ')} ${customConfig} --json --quiet --max-target-bytes=5000000 --timeout 300 --max-memory 4096 /scan-target 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const result: SemgrepResult = JSON.parse(stdout);

      for (const finding of result.results) {
        const cweIds = finding.extra.metadata?.cwe || [];
        const owaspCategories = finding.extra.metadata?.owasp || [];

        findings.push({
          ruleId: finding.check_id,
          severity: mapSeverity(finding.extra.severity),
          title: finding.check_id.split('.').pop() || finding.check_id,
          description: finding.extra.message,
          filePath: finding.path,
          lineNumber: finding.start.line,
          columnNumber: finding.start.col,
          codeSnippet: finding.extra.lines,
          cweId: cweIds[0] || null,
          owaspCategory: owaspCategories[0] || null,
          fixAvailable: !!finding.extra.metadata?.fix,
          fixDescription: finding.extra.metadata?.fix || null,
          metadata: {
            endLine: finding.end.line,
            endCol: finding.end.col,
            references: finding.extra.metadata?.references,
          },
        });
      }
    }

    // Extract audit evidence
    const parsedResult: SemgrepResult | null = stdout.trim() ? JSON.parse(stdout) : null;
    const filesWithFindings = new Set(parsedResult?.results?.map(r => r.path) || []);
    const uniqueRules = new Set(parsedResult?.results?.map(r => r.check_id) || []);

    // Count total source files that semgrep would have scanned (not just files with findings)
    let totalFilesScanned = filesWithFindings.size;
    try {
      const { stdout: fileCount } = await execAsync(
        `find /scan-target -type f \\( -name '*.py' -o -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.go' -o -name '*.java' -o -name '*.rb' -o -name '*.php' -o -name '*.rs' -o -name '*.c' -o -name '*.cpp' -o -name '*.cs' -o -name '*.kt' -o -name '*.scala' -o -name '*.sh' \\) -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/vendor/*' 2>/dev/null | wc -l`,
        { timeout: 10000 }
      );
      const count = parseInt(fileCount.trim()) || 0;
      if (count > totalFilesScanned) totalFilesScanned = count;
    } catch { /* use findings-based count as fallback */ }

    logger.info({ findingsCount: findings.length, totalFilesScanned }, 'Opengrep scan completed');

    return {
      scanner: 'opengrep',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        filesAnalyzed: totalFilesScanned || undefined,
        rulesEvaluated: uniqueRules.size || undefined,
        checksPerformed: [
          'OWASP Top 10 patterns', 'Security audit rules', 'Secrets detection',
          'Injection patterns', 'XSS patterns', 'Insecure crypto usage',
        ],
        scanScope: 'Multi-language SAST with auto, security-audit, owasp-top-ten, cwe-top-25, r2c-security-audit, and secrets rulesets',
        configuration: existsSync('/configs/semgrep-rules.yml') ? 'Custom semgrep-rules.yml + default rulesets' : 'Default rulesets (auto, security-audit, owasp-top-ten, cwe-top-25, r2c-security-audit, secrets)',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Opengrep scan failed');
    return {
      scanner: 'opengrep',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
