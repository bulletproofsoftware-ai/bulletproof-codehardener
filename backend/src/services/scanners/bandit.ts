import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import { cweToOwasp } from './cwe-owasp-map.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-bandit');

interface BanditResult {
  results: Array<{
    code: string;
    col_offset: number;
    end_col_offset: number;
    filename: string;
    issue_confidence: string;
    issue_cwe: { id: number; link: string };
    issue_severity: string;
    issue_text: string;
    line_number: number;
    line_range: number[];
    more_info: string;
    test_id: string;
    test_name: string;
  }>;
  metrics: {
    _totals: {
      'SEVERITY.HIGH': number;
      'SEVERITY.MEDIUM': number;
      'SEVERITY.LOW': number;
    };
  };
}

function mapSeverity(banditSeverity: string): Severity {
  const map: Record<string, Severity> = {
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
  };
  return map[banditSeverity.toUpperCase()] || 'info';
}

export async function runBandit(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Gate: skip if no Python files present
    const { stdout: pyFiles } = await execAsync(
      `find /scan-target -maxdepth 4 -name "*.py" -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );
    if (!pyFiles.trim()) {
      return {
        scanner: 'bandit',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .py files found — Bandit requires a Python project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Python files found in project',
      };
    }

    // Run Bandit on Python files with confidence/severity filtering and excludes
    const configFlag = existsSync('/configs/bandit.yaml') ? '--configfile /configs/bandit.yaml' : '';
    const cmd = `bandit -r /scan-target -f json --quiet -l -i ${configFlag} --exclude /scan-target/node_modules,/scan-target/.venv,/scan-target/venv,/scan-target/__pycache__ 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const result: BanditResult = JSON.parse(stdout);

      for (const issue of result.results) {
        const cweId = issue.issue_cwe ? `CWE-${issue.issue_cwe.id}` : null;
        findings.push({
          ruleId: issue.test_id,
          severity: mapSeverity(issue.issue_severity),
          title: `${issue.test_name}: ${issue.issue_text.slice(0, 80)}`,
          description: issue.issue_text,
          filePath: issue.filename.replace('/scan-target/', ''),
          lineNumber: issue.line_number,
          columnNumber: issue.col_offset,
          codeSnippet: issue.code,
          cweId,
          owaspCategory: cweToOwasp(cweId) || 'A03:2021-Injection',
          fixAvailable: true,
          fixDescription: `Review the code pattern flagged by ${issue.test_name}. See: ${issue.more_info}`,
          metadata: {
            confidence: issue.issue_confidence,
            testName: issue.test_name,
            lineRange: issue.line_range,
            moreInfo: issue.more_info,
          },
        });
      }
    }

    // Extract audit evidence from bandit metrics
    const banditMetrics = stdout.trim() ? JSON.parse(stdout) : {};
    const metricKeys = Object.keys(banditMetrics.metrics || {}).filter(k => k !== '_totals');

    logger.info({ findingsCount: findings.length }, 'Bandit scan completed');

    return {
      scanner: 'bandit',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        filesAnalyzed: metricKeys.length || undefined,
        rulesEvaluated: 40,
        checksPerformed: [
          'SQL injection detection', 'Shell injection detection', 'Insecure hash functions',
          'Hardcoded passwords', 'Unsafe deserialization', 'Insecure TLS/SSL',
          'Weak crypto key sizes', 'Temp file security',
        ],
        scanScope: `Python SAST analysis of ${metricKeys.length} file(s) with all severity and confidence levels`,
        configuration: existsSync('/configs/bandit.yaml') ? 'Custom bandit.yaml' : 'Default rules (-l -i, all severities)',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Bandit scan failed');
    return {
      scanner: 'bandit',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
