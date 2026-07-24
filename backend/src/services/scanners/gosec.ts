import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import { cweToOwasp } from './cwe-owasp-map.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-gosec');

interface GosecResult {
  Issues: Array<{
    severity: string;
    confidence: string;
    cwe: { id: string; url: string };
    rule_id: string;
    details: string;
    file: string;
    code: string;
    line: string;
    column: string;
    nosec: boolean;
    suppressions?: Array<{ kind: string; justification: string }>;
  }>;
  Stats: {
    files: number;
    lines: number;
    nosec: number;
    found: number;
  };
}

function mapSeverity(gosecSeverity: string): Severity {
  const map: Record<string, Severity> = {
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
  };
  return map[gosecSeverity.toUpperCase()] || 'info';
}

export async function runGosec(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Gate: skip if no Go files present
    const { stdout: goFiles } = await execAsync(
      `find /scan-target -maxdepth 4 -name "*.go" -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );
    if (!goFiles.trim()) {
      return {
        scanner: 'gosec',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .go files found — Gosec requires a Go project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Go files found in project',
      };
    }

    // Run Gosec on Go files
    const configFlag = existsSync('/configs/gosec-config.json') ? '-conf=/configs/gosec-config.json' : '';
    const cmd = `gosec -fmt=json -quiet ${configFlag} -severity=low -confidence=low -tests -track-suppressions -exclude-dir=vendor -exclude-dir=testdata /scan-target/... 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const result: GosecResult = JSON.parse(stdout);

      for (const issue of result.Issues || []) {
        // Skip nosec annotated issues
        if (issue.nosec) continue;

        const cweId = issue.cwe ? `CWE-${issue.cwe.id}` : null;
        findings.push({
          ruleId: issue.rule_id,
          severity: mapSeverity(issue.severity),
          title: `Go Security Issue: ${issue.details.slice(0, 80)}`,
          description: issue.details,
          filePath: issue.file.replace('/scan-target/', ''),
          lineNumber: parseInt(issue.line) || null,
          columnNumber: parseInt(issue.column) || null,
          codeSnippet: issue.code,
          cweId,
          owaspCategory: cweToOwasp(cweId) || 'A03:2021-Injection',
          fixAvailable: true,
          fixDescription: issue.cwe
            ? `Address the security issue. Reference: ${issue.cwe.url}`
            : 'Review and fix the security concern in this Go code.',
          metadata: {
            confidence: issue.confidence,
            ruleId: issue.rule_id,
            suppressions: issue.suppressions,
          },
        });
      }
    }

    // Extract audit evidence
    const gosecResult = stdout.trim() ? JSON.parse(stdout) : {};
    const stats = gosecResult.Stats || {};

    logger.info({ findingsCount: findings.length }, 'Gosec scan completed');

    return {
      scanner: 'gosec',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'SQL injection detection', 'Command injection detection', 'Hardcoded credentials',
          'Insecure crypto usage', 'Unsafe file permissions', 'Race conditions',
          'Error handling issues', 'Test file security scanning',
        ],
        scanScope: `Go SAST analysis of ${stats.files || 0} files (${stats.lines || 0} lines), including test files`,
        filesAnalyzed: stats.files || undefined,
        rulesEvaluated: stats.found || undefined,
        configuration: existsSync('/configs/gosec-config.json')
          ? 'Custom gosec-config.json with suppression tracking'
          : 'Default rules, all severities/confidence, test files included, suppression tracking enabled',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Gosec scan failed');
    return {
      scanner: 'gosec',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
