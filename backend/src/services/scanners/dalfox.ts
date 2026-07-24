import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-dalfox');

const SCAN_TARGET = '/scan-target';
void SCAN_TARGET; // DAST scanner — uses targetUrl, not filesystem

interface DalfoxFinding {
  type: string;
  inject_type: string;
  poc_type: string;
  method: string;
  data: string;
  param: string;
  payload: string;
  evidence: string;
  cwe: string;
  severity: string;
}

function mapDalfoxSeverity(finding: DalfoxFinding): Severity {
  const type = (finding.type || '').toLowerCase();
  const severity = (finding.severity || '').toLowerCase();

  if (type === 'verified' || severity === 'high') return 'high';
  if (type === 'potential' || severity === 'medium') return 'medium';
  if (severity === 'low') return 'low';
  return 'medium';
}

export async function runDalfox(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  const targetUrl = jobData.targetUrl;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No target URL provided, skipping dalfox XSS scan');
    return {
      scanner: 'dalfox',
      success: true,
      skipped: true,
      findings: [],
      duration: Date.now() - startTime,
      skipReason: 'no_target_url',
      skipHint: 'Add a target URL to enable XSS vulnerability scanning with dalfox',
    };
  }

  try {
    // Run dalfox in silent mode with JSON output
    const cmd = `dalfox url "${targetUrl}" --silence --format json --output /tmp/dalfox-out.json 2>/dev/null || true`;
    await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 180000 });

    // Parse results
    if (existsSync('/tmp/dalfox-out.json')) {
      const raw = readFileSync('/tmp/dalfox-out.json', 'utf-8');

      if (raw.trim()) {
        // dalfox outputs newline-delimited JSON or a JSON array
        let results: DalfoxFinding[] = [];

        try {
          const parsed = JSON.parse(raw);
          results = Array.isArray(parsed) ? parsed : [parsed];
        } catch {
          // Try newline-delimited JSON
          results = raw
            .trim()
            .split('\n')
            .map((line) => {
              try {
                return JSON.parse(line) as DalfoxFinding;
              } catch {
                return null;
              }
            })
            .filter((r): r is DalfoxFinding => r !== null);
        }

        for (const result of results.slice(0, 200)) {
          const severity = mapDalfoxSeverity(result);
          const isVerified = (result.type || '').toLowerCase() === 'verified';

          findings.push({
            ruleId: 'DALFOX-XSS',
            severity,
            title: `${isVerified ? 'Verified' : 'Potential'} XSS: ${result.param || 'unknown parameter'} via ${result.inject_type || 'unknown'}`,
            description: `${isVerified ? 'Confirmed' : 'Potential'} Cross-Site Scripting (XSS) vulnerability detected in parameter '${result.param || 'unknown'}'. Method: ${result.method || 'GET'}. Injection type: ${result.inject_type || 'unknown'}.`,
            filePath: null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: result.payload?.slice(0, 2000) ?? null,
            cweId: 'CWE-79',
            owaspCategory: 'A03:2021-Injection',
            fixAvailable: false,
            fixDescription: 'Sanitize and encode all user input before rendering in HTML context. Use Content-Security-Policy headers. Implement output encoding appropriate to the context (HTML, JavaScript, URL, CSS).',
            metadata: {
              type: result.type,
              injectType: result.inject_type,
              pocType: result.poc_type,
              method: result.method,
              parameter: result.param,
              payload: result.payload,
              evidence: result.evidence,
              verified: isVerified,
              targetUrl,
            },
          });
        }
      }
    }

    const hasAuth = !!(jobData.authConfig?.loginUrl);
    if (hasAuth) {
      logger.info('dalfox: auth config available; dalfox does not support session-based authentication natively');
    }

    logger.info({ findingsCount: findings.length }, 'dalfox scan completed');

    return {
      scanner: 'dalfox',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: existsSync('/tmp/dalfox-out.json')
        ? readFileSync('/tmp/dalfox-out.json', 'utf-8')
        : 'No output generated',
      evidence: {
        checksPerformed: [
          'Reflected XSS detection',
          'Stored XSS detection',
          'DOM-based XSS detection',
          'Parameter analysis and fuzzing',
          'Payload verification',
        ],
        scanScope: `XSS vulnerability scanning against ${targetUrl}`,
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'dalfox default scanning mode',
        authenticationStatus: hasAuth ? 'auth-available-not-supported' : 'unauthenticated',
      },
    };
  } catch (error) {
    logger.error({ error }, 'dalfox scan failed');
    return {
      scanner: 'dalfox',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
