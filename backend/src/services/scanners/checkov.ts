import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-checkov');

interface CheckovResult {
  check_type: string;
  results: {
    passed_checks: Array<any>;
    failed_checks: Array<{
      check_id: string;
      bc_check_id?: string;
      check_name: string;
      check_result: { result: string };
      file_path: string;
      file_line_range: [number, number];
      resource: string;
      guideline?: string;
      severity?: string;
    }>;
    skipped_checks: Array<any>;
  };
}

function mapSeverity(checkovSeverity?: string): Severity {
  if (!checkovSeverity) return 'medium';
  const map: Record<string, Severity> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
  };
  return map[checkovSeverity.toUpperCase()] || 'medium';
}

export async function runCheckov(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Gate: skip if no IaC files present
    const { stdout: iacFiles } = await execAsync(
      `find /scan-target -maxdepth 4 \\( -name "*.tf" -o -name "*.yaml" -o -name "*.yml" -o -name "Dockerfile" -o -name "*.hcl" \\) -not -path "*/node_modules/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );
    if (!iacFiles.trim()) {
      return {
        scanner: 'checkov',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No IaC files found (Terraform, YAML, Dockerfile) — Checkov requires infrastructure-as-code files',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No IaC files found in project',
      };
    }

    // Run Checkov for IaC scanning
    const configFlag = existsSync('/configs/.checkov.yaml') ? '--config-file /configs/.checkov.yaml' : '';
    const cmd = `checkov -d /scan-target --output json --quiet ${configFlag} --framework terraform,cloudformation,kubernetes,dockerfile,helm,serverless,arm,bicep,ansible,github_actions,gitlab_ci,secrets --compact 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      // Checkov can output multiple results for different frameworks
      const results: CheckovResult[] = Array.isArray(JSON.parse(stdout))
        ? JSON.parse(stdout)
        : [JSON.parse(stdout)];

      for (const result of results) {
        if (!result.results?.failed_checks) continue;

        for (const check of result.results.failed_checks) {
          findings.push({
            ruleId: check.check_id,
            severity: mapSeverity(check.severity),
            title: check.check_name,
            description: `IaC misconfiguration detected in ${check.resource}. ${check.check_name}`,
            filePath: check.file_path,
            lineNumber: check.file_line_range[0],
            columnNumber: null,
            codeSnippet: `Resource: ${check.resource}`,
            cweId: null,
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: !!check.guideline,
            fixDescription: check.guideline || null,
            metadata: {
              checkType: result.check_type,
              bcCheckId: check.bc_check_id,
              lineRange: check.file_line_range,
            },
          });
        }
      }
    }

    // Extract audit evidence from Checkov results
    const checkovResults: CheckovResult[] = stdout.trim()
      ? (Array.isArray(JSON.parse(stdout)) ? JSON.parse(stdout) : [JSON.parse(stdout)])
      : [];
    const totalChecks = checkovResults.reduce((sum, r) =>
      sum + (r.results?.passed_checks?.length || 0) + (r.results?.failed_checks?.length || 0) + (r.results?.skipped_checks?.length || 0), 0);
    const passedChecks = checkovResults.reduce((sum, r) => sum + (r.results?.passed_checks?.length || 0), 0);
    const frameworks = checkovResults.map(r => r.check_type).filter(Boolean);
    const uniqueFiles = new Set(checkovResults.flatMap(r =>
      [...(r.results?.passed_checks || []), ...(r.results?.failed_checks || [])].map(c => c.file_path)
    ));

    logger.info({ findingsCount: findings.length, totalChecks, passedChecks }, 'Checkov scan completed');

    return {
      scanner: 'checkov',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        filesAnalyzed: uniqueFiles.size,
        rulesEvaluated: totalChecks,
        checksPerformed: [
          'Terraform misconfigurations', 'CloudFormation template issues',
          'Kubernetes manifest hardening', 'Dockerfile best practices',
          'Helm chart security', 'GitHub Actions security',
          'GitLab CI security', 'Secrets in IaC files',
        ],
        scanScope: `IaC security analysis — ${uniqueFiles.size} files, ${totalChecks} checks (${passedChecks} passed, ${findings.length} failed), frameworks: ${frameworks.join(', ') || 'auto-detected'}`,
        configuration: existsSync('/configs/.checkov.yaml') ? 'Custom .checkov.yaml' : 'Default rules across all supported frameworks',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Checkov scan failed');
    return {
      scanner: 'checkov',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
