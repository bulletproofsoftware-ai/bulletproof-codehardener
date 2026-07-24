import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-nuclei');

interface NucleiResult {
  'template-id': string;
  'template-path': string;
  info: {
    name: string;
    author: string[];
    tags: string[];
    severity: string;
    description?: string;
    reference?: string[];
    classification?: {
      'cve-id'?: string[];
      'cwe-id'?: string[];
    };
  };
  host: string;
  matched: string;
  'matched-at': string;
  'extracted-results'?: string[];
  timestamp: string;
}

function mapSeverity(nucleiSeverity: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
  };
  return map[nucleiSeverity.toLowerCase()] || 'info';
}

export async function runNuclei(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  // Nuclei is for DAST - only run if we have a URL target
  const targetUrl = jobData.targetUrl;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No target URL provided, skipping Nuclei DAST scan');
    return {
      scanner: 'nuclei',
      success: true,
      skipped: true,
      skipReason: 'no_target_url',
      skipHint: 'Add Application URL in Project Settings to enable DAST scanning',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  try {
    // Run Nuclei with expanded security templates, rate limiting, and severity filtering
    const url = targetUrl;
    const templateDirs = ['-t cves/', '-t vulnerabilities/', '-t exposures/', '-t misconfiguration/', '-t default-logins/', '-t file/', '-t network/', '-t dns/', '-t technologies/', '-t cloud/'];
    const customTemplates = existsSync('/nuclei-templates') ? '-t /nuclei-templates/' : '';
    const customDir = existsSync('/configs/nuclei-custom') ? '-t /configs/nuclei-custom/' : '';
    const cmd = `nuclei -u ${url} ${templateDirs.join(' ')} ${customTemplates} ${customDir} -json -silent -severity critical,high,medium,low -rate-limit 150 -timeout 10 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
    );

    if (stdout.trim()) {
      // Nuclei outputs newline-delimited JSON
      const lines = stdout.trim().split('\n');

      for (const line of lines) {
        try {
          const result: NucleiResult = JSON.parse(line);

          const cweIds = result.info.classification?.['cwe-id'] || [];
          const cveIds = result.info.classification?.['cve-id'] || [];

          findings.push({
            ruleId: result['template-id'],
            severity: mapSeverity(result.info.severity),
            title: result.info.name,
            description: result.info.description || `Vulnerability detected: ${result.info.name}`,
            filePath: null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: `Matched: ${result.matched}\nURL: ${result['matched-at']}`,
            cweId: cweIds[0] || null,
            owaspCategory: null,
            fixAvailable: (result.info.reference?.length || 0) > 0,
            fixDescription: result.info.reference?.join(', ') || null,
            metadata: {
              host: result.host,
              matchedAt: result['matched-at'],
              tags: result.info.tags,
              author: result.info.author,
              cveIds,
              extractedResults: result['extracted-results'],
            },
          });
        } catch {
          // Skip malformed JSON lines
        }
      }
    }

    const hasAuth = !!(jobData.authConfig?.loginUrl);
    if (hasAuth) {
      logger.info('Nuclei: auth config available but Nuclei runs template-based checks without session authentication');
    }

    logger.info({ findingsCount: findings.length }, 'Nuclei scan completed');

    return {
      scanner: 'nuclei',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'CVE template matching',
          'Misconfiguration detection',
          'Default credentials testing',
          'Exposure detection',
          'Technology fingerprinting',
        ],
        scanScope: `Template-based vulnerability scanning against ${targetUrl}`,
        configuration: 'Nuclei with expanded security templates, rate-limit 150, severity critical-low',
        authenticationStatus: hasAuth ? 'auth-available-not-supported' : 'unauthenticated',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Nuclei scan failed');
    return {
      scanner: 'nuclei',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
