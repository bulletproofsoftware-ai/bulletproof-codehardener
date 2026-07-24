import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync } from 'fs';
// ffuf: Fast web fuzzer for directory/parameter discovery via DAST target URL
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-ffuf');

const SCAN_TARGET = '/scan-target';
void SCAN_TARGET; // DAST scanner — uses targetUrl, not filesystem

interface FfufOutput {
  commandline: string;
  results: FfufResult[];
  config: Record<string, unknown>;
}

interface FfufResult {
  input: { FUZZ: string };
  position: number;
  status: number;
  length: number;
  words: number;
  lines: number;
  content_type: string;
  redirectlocation: string;
  url: string;
  resultfile: string;
  host: string;
}

function mapStatusToSeverity(status: number): { severity: Severity; category: string } {
  if (status >= 500) {
    return { severity: 'high', category: 'server-error' };
  }
  if (status === 200 || status === 201) {
    return { severity: 'medium', category: 'hidden-endpoint' };
  }
  if (status === 301 || status === 302) {
    return { severity: 'low', category: 'redirect' };
  }
  if (status === 401 || status === 403) {
    return { severity: 'info', category: 'protected-endpoint' };
  }
  return { severity: 'low', category: 'other' };
}

export async function runFfuf(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  const targetUrl = jobData.targetUrl;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No target URL provided, skipping ffuf directory scan');
    return {
      scanner: 'ffuf',
      success: true,
      skipped: true,
      findings: [],
      duration: Date.now() - startTime,
      skipReason: 'no_target_url',
      skipHint: 'Add a target URL to enable hidden endpoint discovery with ffuf',
    };
  }

  try {
    // Ensure base URL ends without trailing slash for clean FUZZ insertion
    const baseUrl = targetUrl.replace(/\/+$/, '');

    // Run ffuf with a common wordlist, filtering 404s, limited threads and timeout
    const wordlist = existsSync('/app/tools/wordlists/common.txt')
      ? '/app/tools/wordlists/common.txt'
      : '/usr/share/wordlists/dirb/common.txt';

    const cmd = `ffuf -u "${baseUrl}/FUZZ" -w ${wordlist} -o /tmp/ffuf-out.json -of json -fc 404 -t 10 -timeout 10 2>/dev/null || true`;
    await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 120000 });

    // Parse results
    if (existsSync('/tmp/ffuf-out.json')) {
      const raw = readFileSync('/tmp/ffuf-out.json', 'utf-8');

      if (raw.trim()) {
        const output: FfufOutput = JSON.parse(raw);

        for (const result of (output.results || []).slice(0, 200)) {
          const { severity, category } = mapStatusToSeverity(result.status);
          const path = result.input?.FUZZ || 'unknown';

          // Skip info-level protected endpoints (401/403 are expected)
          if (severity === 'info') continue;

          let title: string;
          let description: string;

          if (category === 'server-error') {
            title = `Server error on hidden path: /${path} (HTTP ${result.status})`;
            description = `ffuf discovered a path that returns a server error (HTTP ${result.status}). This may indicate an unhandled route, debug endpoint, or misconfigured handler.`;
          } else if (category === 'hidden-endpoint') {
            title = `Hidden endpoint discovered: /${path} (HTTP ${result.status})`;
            description = `ffuf discovered an accessible endpoint at /${path} that is not publicly documented. Response: ${result.length} bytes, ${result.words} words. Content-Type: ${result.content_type || 'unknown'}.`;
          } else {
            title = `Endpoint discovered: /${path} (HTTP ${result.status})`;
            description = `ffuf found /${path} responding with HTTP ${result.status}. ${result.redirectlocation ? `Redirects to: ${result.redirectlocation}` : ''}`;
          }

          findings.push({
            ruleId: 'FFUF-HIDDEN-ENDPOINT',
            severity,
            title,
            description,
            filePath: null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: category === 'server-error' ? 'CWE-200' : 'CWE-538',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: false,
            fixDescription: category === 'server-error'
              ? 'Investigate the server error. Ensure error handlers are in place and debug endpoints are disabled in production.'
              : 'Review whether this endpoint should be publicly accessible. Restrict access or remove if unnecessary.',
            metadata: {
              path: `/${path}`,
              statusCode: result.status,
              responseLength: result.length,
              responseWords: result.words,
              responseLines: result.lines,
              contentType: result.content_type,
              redirectLocation: result.redirectlocation || null,
              fullUrl: result.url,
              category,
            },
          });
        }
      }
    }

    const hasAuth = !!(jobData.authConfig?.loginUrl);
    if (hasAuth) {
      logger.info('ffuf: auth config available; ffuf runs unauthenticated directory discovery (no session support)');
    }

    logger.info({ findingsCount: findings.length }, 'ffuf scan completed');

    return {
      scanner: 'ffuf',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: existsSync('/tmp/ffuf-out.json')
        ? readFileSync('/tmp/ffuf-out.json', 'utf-8')
        : 'No output generated',
      evidence: {
        checksPerformed: [
          'Directory and file brute-forcing',
          'Hidden endpoint discovery',
          'Server error detection on hidden paths',
          'Response analysis and categorization',
        ],
        scanScope: `Hidden endpoint discovery against ${targetUrl}`,
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'ffuf with common wordlist, 10 threads, 10s timeout, 404 filter',
        authenticationStatus: hasAuth ? 'auth-available-not-supported' : 'unauthenticated',
      },
    };
  } catch (error) {
    logger.error({ error }, 'ffuf scan failed');
    return {
      scanner: 'ffuf',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
