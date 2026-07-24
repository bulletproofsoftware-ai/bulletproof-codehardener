import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-kubeconform');

const SCAN_TARGET = '/scan-target';

interface KubeconformResource {
  filename: string;
  kind: string;
  name: string;
  version: string;
  status: 'Valid' | 'Invalid' | 'Error' | 'Skipped';
  msg: string;
  validationErrors: Array<{ path: string; msg: string }>;
}

interface KubeconformOutput {
  resources: KubeconformResource[];
  summary: {
    valid: number;
    invalid: number;
    errors: number;
    skipped: number;
  };
}

function statusToSeverity(status: string): Severity {
  if (status === 'Invalid') return 'high';
  if (status === 'Error') return 'medium';
  return 'low';
}

export async function runKubeconform(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Find YAML files that are Kubernetes manifests
    const { stdout: yamlFiles } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 5 \\( -name "*.yaml" -o -name "*.yml" \\) -not -path "*/node_modules/*" -not -path "*/.github/*" 2>/dev/null`,
      { maxBuffer: 10 * 1024 * 1024 }
    );

    if (!yamlFiles.trim()) {
      return {
        scanner: 'kubeconform',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No YAML files found — Kubeconform requires Kubernetes manifest YAML files',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No YAML files found',
      };
    }

    // Check if any YAML files contain Kubernetes manifests (kind: + apiVersion:)
    const { stdout: k8sCheck } = await execAsync(
      `grep -rl "kind:" ${SCAN_TARGET} --include="*.yaml" --include="*.yml" 2>/dev/null | xargs grep -l "apiVersion:" 2>/dev/null | head -1`,
      { maxBuffer: 10 * 1024 * 1024 }
    );

    if (!k8sCheck.trim()) {
      logger.info('No Kubernetes manifests found');
      return {
        scanner: 'kubeconform',
        success: true,
        skipped: true,
        skipReason: 'no_k8s_manifests',
        skipHint: 'YAML files exist but none contain Kubernetes markers (kind: + apiVersion:)',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Kubernetes manifests found (no files with kind: and apiVersion:)',
      };
    }

    // Run kubeconform on all YAML files
    const { stdout } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 5 \\( -name "*.yaml" -o -name "*.yml" \\) -not -path "*/node_modules/*" | xargs kubeconform -output json -summary 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 60000 }
    );

    if (!stdout.trim()) {
      return {
        scanner: 'kubeconform',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No output from kubeconform',
      };
    }

    let output: KubeconformOutput;
    try {
      output = JSON.parse(stdout.trim());
    } catch {
      // kubeconform may output one JSON object per line (NDJSON)
      const lines = stdout.trim().split('\n').filter(Boolean);
      const resources: KubeconformResource[] = [];
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.resources) {
            resources.push(...parsed.resources);
          } else if (parsed.filename) {
            resources.push(parsed);
          }
        } catch {
          // skip unparseable lines
        }
      }
      output = {
        resources,
        summary: {
          valid: resources.filter(r => r.status === 'Valid').length,
          invalid: resources.filter(r => r.status === 'Invalid').length,
          errors: resources.filter(r => r.status === 'Error').length,
          skipped: resources.filter(r => r.status === 'Skipped').length,
        },
      };
    }

    const resources = output.resources || [];

    for (const resource of resources) {
      // Skip valid and skipped resources
      if (resource.status === 'Valid' || resource.status === 'Skipped') continue;

      const cleanPath = (resource.filename || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      const ruleId = resource.status === 'Invalid' ? 'KUBECONFORM-INVALID' : 'KUBECONFORM-ERROR';
      const severity = statusToSeverity(resource.status);

      if (resource.validationErrors && resource.validationErrors.length > 0) {
        for (const valError of resource.validationErrors) {
          findings.push({
            ruleId,
            severity,
            title: `Kubernetes ${resource.status}: ${resource.kind || 'Unknown'}/${resource.name || 'unnamed'} — ${valError.path || 'schema'}`,
            description: `${valError.msg}${resource.msg ? `\n\nResource message: ${resource.msg}` : ''}`,
            filePath: cleanPath || null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: `Kind: ${resource.kind || 'Unknown'}, Name: ${resource.name || 'unnamed'}, Version: ${resource.version || 'unknown'}, Path: ${valError.path || '/'}`,
            cweId: null,
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: true,
            fixDescription: `Fix the validation error at path "${valError.path || '/'}" in ${resource.kind || 'resource'} "${resource.name || 'unnamed'}". ${valError.msg}`,
            metadata: {
              kind: resource.kind,
              name: resource.name,
              version: resource.version,
              status: resource.status,
              validationPath: valError.path,
            },
          });
        }
      } else {
        // Resource-level error with no specific validation errors
        findings.push({
          ruleId,
          severity,
          title: `Kubernetes ${resource.status}: ${resource.kind || 'Unknown'}/${resource.name || 'unnamed'}`,
          description: resource.msg || `${resource.status} Kubernetes resource detected`,
          filePath: cleanPath || null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: `Kind: ${resource.kind || 'Unknown'}, Name: ${resource.name || 'unnamed'}, Version: ${resource.version || 'unknown'}`,
          cweId: null,
          owaspCategory: 'A05:2021-Security Misconfiguration',
          fixAvailable: true,
          fixDescription: `Fix the ${resource.status.toLowerCase()} Kubernetes manifest for ${resource.kind || 'resource'} "${resource.name || 'unnamed'}". ${resource.msg || ''}`.trim(),
          metadata: {
            kind: resource.kind,
            name: resource.name,
            version: resource.version,
            status: resource.status,
          },
        });
      }
    }

    const summary = output.summary || {
      valid: resources.filter(r => r.status === 'Valid').length,
      invalid: resources.filter(r => r.status === 'Invalid').length,
      errors: resources.filter(r => r.status === 'Error').length,
      skipped: resources.filter(r => r.status === 'Skipped').length,
    };
    const totalResources = summary.valid + summary.invalid + summary.errors + summary.skipped;
    const uniqueFiles = new Set(resources.map(r => r.filename).filter(Boolean));

    logger.info({ findingsCount: findings.length, totalResources, valid: summary.valid, invalid: summary.invalid, errors: summary.errors }, 'kubeconform scan completed');

    return {
      scanner: 'kubeconform',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        filesAnalyzed: uniqueFiles.size,
        rulesEvaluated: totalResources,
        checksPerformed: [
          'Kubernetes manifest schema validation',
          'API version compatibility checks',
          'Resource spec conformance',
          'Required field validation',
        ],
        scanScope: `Kubernetes manifest validation — ${uniqueFiles.size} files, ${totalResources} resources (${summary.valid} valid, ${summary.invalid} invalid, ${summary.errors} errors, ${summary.skipped} skipped)`,
        configuration: 'Default Kubernetes JSON schemas',
      },
    };
  } catch (error) {
    logger.error({ error }, 'kubeconform scan failed');
    return {
      scanner: 'kubeconform',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
