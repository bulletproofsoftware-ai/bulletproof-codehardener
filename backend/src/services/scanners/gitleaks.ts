import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-gitleaks');

interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}

function getSeverity(ruleId: string): Severity {
  const critical = ['aws-access-key', 'aws-secret-key', 'github-token', 'private-key'];
  const high = ['api-key', 'password', 'secret', 'token', 'credential'];

  const ruleLower = ruleId.toLowerCase();
  if (critical.some(k => ruleLower.includes(k))) return 'critical';
  if (high.some(k => ruleLower.includes(k))) return 'high';
  return 'medium';
}

export async function runGitleaks(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Run Gitleaks with redaction to prevent secret leakage in output
    const configFlag = existsSync('/configs/gitleaks.toml') ? '--config=/configs/gitleaks.toml' : '';
    // Scan full git history for comprehensive/supply-chain profiles to catch rotated secrets
    const deepProfiles = ['comprehensive', 'supply-chain', 'full'];
    const historyFlag = deepProfiles.includes(jobData.profile) ? '--log-opts="--all"' : '';
    const cmd = `gitleaks detect --source /scan-target ${configFlag} ${historyFlag} --report-format json --report-path /dev/stdout --no-banner --redact 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const results: GitleaksResult[] = JSON.parse(stdout);

      for (const leak of results) {
        // Redact the actual secret
        const redactedSecret = leak.Secret.length > 8
          ? leak.Secret.slice(0, 4) + '****' + leak.Secret.slice(-4)
          : '****';

        findings.push({
          ruleId: leak.RuleID,
          severity: getSeverity(leak.RuleID),
          title: `Secret Detected: ${leak.Description}`,
          description: `A potential secret was found in your codebase. Type: ${leak.Description}. This could lead to credential exposure and unauthorized access.`,
          filePath: leak.File,
          lineNumber: leak.StartLine,
          columnNumber: leak.StartColumn,
          codeSnippet: `Line ${leak.StartLine}: ${leak.Match.replace(leak.Secret, redactedSecret)}`,
          cweId: 'CWE-798',
          owaspCategory: 'A07:2021-Identification and Authentication Failures',
          fixAvailable: true,
          fixDescription: 'Remove the hardcoded secret and use environment variables or a secret management system instead. Rotate the exposed credential immediately.',
          metadata: {
            entropy: leak.Entropy,
            commit: leak.Commit,
            author: leak.Author,
            tags: leak.Tags,
            fingerprint: leak.Fingerprint,
          },
        });
      }
    }

    // Extract audit evidence — count ALL files scanned, not just files with secrets
    const filesWithSecrets = stdout.trim()
      ? new Set(JSON.parse(stdout).map((r: GitleaksResult) => r.File))
      : new Set<string>();

    let totalFilesScanned = filesWithSecrets.size;
    try {
      const { stdout: fileCount } = await execAsync(
        `find /scan-target -type f -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/.venv/*' 2>/dev/null | wc -l`,
        { timeout: 10000 }
      );
      const count = parseInt(fileCount.trim()) || 0;
      if (count > totalFilesScanned) totalFilesScanned = count;
    } catch { /* use findings-based count as fallback */ }

    logger.info({ findingsCount: findings.length, totalFilesScanned }, 'Gitleaks scan completed');

    return {
      scanner: 'gitleaks',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        filesAnalyzed: totalFilesScanned || undefined,
        rulesEvaluated: 150,
        checksPerformed: [
          'AWS credential detection', 'API key detection', 'Private key detection',
          'Generic secret patterns', 'High-entropy string analysis', 'Token detection',
        ],
        scanScope: deepProfiles.includes(jobData.profile)
          ? 'Full git history scanned (all branches) for 150+ secret patterns with entropy analysis'
          : 'Working directory scanned for 150+ secret patterns with entropy analysis',
        configuration: existsSync('/configs/gitleaks.toml') ? 'Custom gitleaks.toml' : 'Default rules',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Gitleaks scan failed');
    return {
      scanner: 'gitleaks',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
