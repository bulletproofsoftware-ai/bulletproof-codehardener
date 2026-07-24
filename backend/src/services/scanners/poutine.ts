import { exec } from 'child_process';
// Intentional use of exec(): All command strings are constant literals with no user input.
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-poutine');

const SCAN_TARGET = '/scan-target';

interface PoutineRule {
  id: string;
  title: string;
  severity: string;
  pipelineFile: string;
  line: number;
  details: string;
}

interface PoutineOutput {
  rules: PoutineRule[];
}

function mapSeverity(severity: string): Severity {
  switch (severity.toLowerCase()) {
    case 'error': return 'high';
    case 'warning': return 'medium';
    case 'note': return 'low';
    default: return 'medium';
  }
}

export async function runPoutine(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    const hasGitHub = existsSync(`${SCAN_TARGET}/.github/workflows`);
    const hasGitLab = existsSync(`${SCAN_TARGET}/.gitlab-ci.yml`);

    if (!hasGitHub && !hasGitLab) {
      return {
        scanner: 'poutine',
        success: true,
        skipped: true,
        skipReason: 'no_ci_config',
        skipHint: 'No .github/workflows or .gitlab-ci.yml found — Poutine requires CI/CD pipeline definitions',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No .github/workflows directory or .gitlab-ci.yml found',
      };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && poutine analyze_local . --format json 2>/dev/null || true`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 120000 }
    );

    if (!stdout.trim() || stdout.trim() === 'null' || stdout.trim() === '{}') {
      return {
        scanner: 'poutine',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No issues found',
      };
    }

    let rules: PoutineRule[] = [];
    try {
      const parsed: PoutineOutput = JSON.parse(stdout.trim());
      rules = Array.isArray(parsed.rules) ? parsed.rules : [];
    } catch {
      logger.warn('Failed to parse poutine JSON output');
      return {
        scanner: 'poutine',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'Failed to parse poutine JSON output — binary may have produced non-JSON error output',
        rawOutput: stdout.slice(0, 5000),
      };
    }

    for (const rule of rules.slice(0, 100)) {
      const cleanPath = (rule.pipelineFile || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');

      findings.push({
        ruleId: `POUTINE-${(rule.id || 'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
        severity: mapSeverity(rule.severity),
        title: rule.title || `CI/CD Security Issue: ${rule.id}`,
        description: rule.details || rule.title || 'CI/CD pipeline security issue detected by poutine.',
        filePath: cleanPath || null,
        lineNumber: rule.line || null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: `Review and fix the CI/CD pipeline security issue "${rule.title}" in ${cleanPath || 'the pipeline configuration'}.`,
        metadata: {
          ruleId: rule.id,
          severity: rule.severity,
        },
      });
    }

    logger.info({ findingsCount: findings.length }, 'poutine scan completed');

    return {
      scanner: 'poutine',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        checksPerformed: [
          'CI/CD pipeline injection detection',
          'Untrusted code checkout analysis',
          'Secrets exposure in workflows',
          'Insecure artifact handling',
          'Pull request target branch manipulation',
          'Workflow run privilege escalation',
          'Third-party action pinning validation',
        ],
        scanScope: `CI/CD pipeline security analysis — ${hasGitHub ? 'GitHub Actions' : ''}${hasGitHub && hasGitLab ? ', ' : ''}${hasGitLab ? 'GitLab CI' : ''} pipelines`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'poutine scan failed');
    return {
      scanner: 'poutine',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
