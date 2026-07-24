import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-conftest');

interface ConftestResult {
  filename: string;
  namespace: string;
  successes: number;
  failures: ConftestFailure[];
  warnings: ConftestWarning[];
  exceptions: ConftestException[];
}

interface ConftestFailure {
  msg: string;
  metadata?: Record<string, any>;
}

interface ConftestWarning {
  msg: string;
  metadata?: Record<string, any>;
}

interface ConftestException {
  msg: string;
}

export async function runConftest(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for policy directory
    const { stdout: policyCheck } = await execAsync(
      `test -d /scan-target/policy && echo "exists" || echo "missing"`
    );

    if (policyCheck.trim() !== 'exists') {
      logger.info('No Conftest policy directory found');
      return {
        scanner: 'conftest',
        success: true,
        skipped: true,
        skipReason: 'no_policy_dir',
        skipHint: 'No policy/ directory found — Conftest requires Rego policies in a policy/ directory',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Conftest policy directory found',
      };
    }

    // Find configuration files to test
    const configPatterns = [
      'Dockerfile*',
      '*.yaml',
      '*.yml',
      '*.json',
      'terraform/*.tf',
      'k8s/*.yaml',
      'kubernetes/*.yaml',
    ];

    const rawOutputParts: string[] = [];

    for (const pattern of configPatterns) {
      const { stdout: filesFound } = await execAsync(
        `find /scan-target -name "${pattern}" -type f 2>/dev/null | grep -v node_modules | grep -v .git | head -20`
      );

      const files = filesFound.trim().split('\n').filter(Boolean);

      for (const file of files) {
        try {
          const { stdout, stderr } = await execAsync(
            `conftest test "${file}" --policy /scan-target/policy --output json 2>&1 || true`,
            { timeout: 30000 }
          );

          const output = stdout || stderr;
          rawOutputParts.push(output);
          if (output.trim() && output.startsWith('[')) {
            const results: ConftestResult[] = JSON.parse(output);

            for (const result of results) {
              // Process failures
              for (const failure of result.failures || []) {
                findings.push({
                  ruleId: 'CONFTEST-FAIL',
                  severity: getSeverityFromMessage(failure.msg),
                  title: `Conftest: Policy Violation`,
                  description: failure.msg,
                  filePath: result.filename.replace('/scan-target/', ''),
                  lineNumber: null,
                  columnNumber: null,
                  codeSnippet: null,
                  cweId: getCWEFromMessage(failure.msg),
                  owaspCategory: getOWASPFromMessage(failure.msg),
                  fixAvailable: true,
                  fixDescription: 'Update configuration to comply with policy',
                  metadata: {
                    namespace: result.namespace,
                    ...failure.metadata,
                  },
                });
              }

              // Process warnings
              for (const warning of result.warnings || []) {
                findings.push({
                  ruleId: 'CONFTEST-WARN',
                  severity: 'low',
                  title: `Conftest: Policy Warning`,
                  description: warning.msg,
                  filePath: result.filename.replace('/scan-target/', ''),
                  lineNumber: null,
                  columnNumber: null,
                  codeSnippet: null,
                  cweId: null,
                  owaspCategory: null,
                  fixAvailable: true,
                  fixDescription: 'Consider updating configuration based on policy recommendation',
                  metadata: {
                    namespace: result.namespace,
                    ...warning.metadata,
                  },
                });
              }

              // Process exceptions (policy errors)
              for (const exception of result.exceptions || []) {
                findings.push({
                  ruleId: 'CONFTEST-EXCEPTION',
                  severity: 'medium',
                  title: `Conftest: Policy Exception`,
                  description: exception.msg,
                  filePath: result.filename.replace('/scan-target/', ''),
                  lineNumber: null,
                  columnNumber: null,
                  codeSnippet: null,
                  cweId: null,
                  owaspCategory: 'A04:2021-Insecure Design',
                  fixAvailable: false,
                  fixDescription: 'Review and fix the policy or configuration',
                  metadata: {
                    namespace: result.namespace,
                  },
                });
              }
            }
          }
        } catch {
          // Skip files that can't be tested
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'Conftest policy testing completed');

    return {
      scanner: 'conftest',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n'),
    };
  } catch (error) {
    logger.error({ error }, 'Conftest policy testing failed');
    return {
      scanner: 'conftest',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getSeverityFromMessage(msg: string): Severity {
  const lower = msg.toLowerCase();
  if (lower.includes('critical') || lower.includes('root') || lower.includes('privileged')) {
    return 'critical';
  }
  if (lower.includes('secret') || lower.includes('password') || lower.includes('credential')) {
    return 'high';
  }
  if (lower.includes('warning') || lower.includes('recommend')) {
    return 'low';
  }
  return 'medium';
}

function getCWEFromMessage(msg: string): string | null {
  const lower = msg.toLowerCase();
  if (lower.includes('privileged') || lower.includes('root')) return 'CWE-250';
  if (lower.includes('secret') || lower.includes('password')) return 'CWE-798';
  if (lower.includes('resource limit')) return 'CWE-770';
  return null;
}

function getOWASPFromMessage(msg: string): string | null {
  const lower = msg.toLowerCase();
  if (lower.includes('secret') || lower.includes('password')) return 'A07:2021-Identification and Authentication Failures';
  if (lower.includes('privileged') || lower.includes('root')) return 'A01:2021-Broken Access Control';
  return 'A05:2021-Security Misconfiguration';
}
