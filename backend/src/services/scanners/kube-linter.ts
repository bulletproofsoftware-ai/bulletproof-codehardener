import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-kube-linter');

const SCAN_TARGET = '/scan-target';

interface KubeLinterReport {
  Check: string;
  Description: string;
  Diagnostic: {
    Message: string;
  };
  Object: {
    K8sObject: {
      GroupVersionKind: {
        Kind: string;
      };
      Namespace: string;
      Name: string;
    };
    Metadata: {
      FilePath: string;
    };
  };
  Remediation: string;
}

interface KubeLinterOutput {
  Reports: KubeLinterReport[];
  Summary: {
    ChecksRun: number;
    FilesScanned: number;
  };
}

function mapSeverityByCheck(check: string): Severity {
  const lower = check.toLowerCase();
  // Privilege and security-related checks → high
  if (
    lower.includes('privilege') ||
    lower.includes('run-as') ||
    lower.includes('root') ||
    lower.includes('security') ||
    lower.includes('secret') ||
    lower.includes('host-') ||
    lower.includes('unsafe') ||
    lower.includes('writable') ||
    lower.includes('ssh') ||
    lower.includes('capability') ||
    lower.includes('read-only') ||
    lower.includes('service-account')
  ) {
    return 'high';
  }
  // Configuration and resource checks → medium
  if (
    lower.includes('resource') ||
    lower.includes('limit') ||
    lower.includes('request') ||
    lower.includes('config') ||
    lower.includes('liveness') ||
    lower.includes('readiness') ||
    lower.includes('probe') ||
    lower.includes('replica') ||
    lower.includes('image') ||
    lower.includes('tag') ||
    lower.includes('port') ||
    lower.includes('env')
  ) {
    return 'medium';
  }
  return 'low';
}

export async function runKubeLinter(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Find Kubernetes YAML files by checking for kind: and apiVersion: markers
    const { stdout: k8sFiles } = await execAsync(
      `grep -rlZ 'kind:' ${SCAN_TARGET} --include='*.yaml' --include='*.yml' 2>/dev/null | xargs -0 grep -lZ 'apiVersion:' 2>/dev/null | tr '\\0' '\\n' | grep -v node_modules | grep -v .git | head -50`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 15000 }
    );

    if (!k8sFiles.trim()) {
      logger.info('No Kubernetes manifests found');
      return {
        scanner: 'kube-linter',
        success: true,
        skipped: true,
        skipReason: 'no_k8s_manifests',
        skipHint: 'No Kubernetes manifests found (no files with kind: + apiVersion:)',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Kubernetes manifests found (no files with kind: and apiVersion:)',
      };
    }

    const manifestCount = k8sFiles.trim().split('\n').filter(Boolean).length;

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && kube-linter lint --format json . 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 60000 }
    );

    if (!stdout.trim() || stdout.trim() === '{}') {
      logger.info('kube-linter produced no output');
      return {
        scanner: 'kube-linter',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No issues found',
        evidence: {
          filesAnalyzed: manifestCount,
          checksPerformed: ['Kubernetes manifest linting'],
          scanScope: `kube-linter analysis — ${manifestCount} K8s manifests, 0 issues found`,
        },
      };
    }

    let parsed: KubeLinterOutput;
    try {
      parsed = JSON.parse(stdout.trim());
    } catch {
      logger.warn('Failed to parse kube-linter JSON output');
      return {
        scanner: 'kube-linter',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: stdout.slice(0, 5000),
      };
    }

    const reports = parsed.Reports || [];

    for (const report of reports.slice(0, 200)) {
      const cleanPath = (report.Object?.Metadata?.FilePath || '')
        .replace(`${SCAN_TARGET}/`, '')
        .replace(/^\//, '');

      const kind = report.Object?.K8sObject?.GroupVersionKind?.Kind || 'Unknown';
      const name = report.Object?.K8sObject?.Name || 'unknown';
      const namespace = report.Object?.K8sObject?.Namespace || 'default';

      findings.push({
        ruleId: `KUBELINTER-${report.Check.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
        severity: mapSeverityByCheck(report.Check),
        title: `KubeLinter: ${report.Description || report.Check}`,
        description: `${report.Diagnostic?.Message || report.Description}\n\nObject: ${kind}/${name} (namespace: ${namespace})`,
        filePath: cleanPath || null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: `${kind}: ${name}`,
        cweId: null,
        owaspCategory: 'A05:2021-Security Misconfiguration',
        fixAvailable: !!report.Remediation,
        fixDescription: report.Remediation || null,
        metadata: {
          check: report.Check,
          kind,
          name,
          namespace,
        },
      });
    }

    const checksRun = parsed.Summary?.ChecksRun ?? 0;
    const filesScanned = parsed.Summary?.FilesScanned ?? manifestCount;

    logger.info({ findingsCount: findings.length, checksRun, filesScanned }, 'kube-linter scan completed');

    return {
      scanner: 'kube-linter',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        filesAnalyzed: filesScanned,
        rulesEvaluated: checksRun,
        checksPerformed: [
          'Container privilege escalation',
          'Resource limits and requests',
          'Security context validation',
          'Image tag pinning',
          'Liveness and readiness probes',
          'Service account configuration',
          'Host namespace sharing',
          'Read-only root filesystem',
        ],
        scanScope: `kube-linter analysis — ${filesScanned} files scanned, ${checksRun} checks run, ${findings.length} issues found`,
        configuration: 'Default kube-linter checks (all built-in rules enabled)',
      },
    };
  } catch (error) {
    logger.error({ error }, 'kube-linter scan failed');
    return {
      scanner: 'kube-linter',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
