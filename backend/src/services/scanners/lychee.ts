import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-lychee');

const SCAN_TARGET = '/scan-target';

interface LycheeOutput {
  fail_map: Record<string, LycheeFailure[]>;
  total: number;
  successful: number;
  failures: number;
  timeouts: number;
  excludes: number;
  errors: number;
}

interface LycheeFailure {
  url: string;
  status: { code?: number; text?: string };
}

function mapStatusToSeverity(status: { code?: number; text?: string }): { severity: Severity; ruleId: string } {
  const text = (status.text || '').toLowerCase();
  if (text.includes('timeout') || status.code === 0) {
    return { severity: 'low', ruleId: 'LYCHEE-TIMEOUT' };
  }
  return { severity: 'medium', ruleId: 'LYCHEE-BROKEN-LINK' };
}

export async function runLychee(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for documentation/HTML files
    const { stdout: fileCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 \\( -name "*.md" -o -name "*.html" -o -name "*.rst" \\) -not -path "*/node_modules/*" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );

    if (!fileCheck.trim()) {
      return {
        scanner: 'lychee',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No .md, .html, or .rst files found in project',
        skipReason: 'no_matching_files',
        skipHint: 'No documentation or HTML files found — Lychee checks links in .md, .html, and .rst files',
      };
    }

    // Run lychee with JSON output
    const cmd = `lychee --format json --no-progress --exclude-loopback --exclude-private ${SCAN_TARGET} 2>/dev/null || true`;
    const { stdout } = await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 120000 });

    if (stdout.trim()) {
      const output: LycheeOutput = JSON.parse(stdout);
      let count = 0;

      for (const [filePath, failures] of Object.entries(output.fail_map || {})) {
        for (const failure of failures) {
          if (count >= 200) break;

          const { severity, ruleId } = mapStatusToSeverity(failure.status);
          const statusDesc = failure.status.code
            ? `HTTP ${failure.status.code}`
            : (failure.status.text || 'Unknown error');

          findings.push({
            ruleId,
            severity,
            title: `${ruleId === 'LYCHEE-TIMEOUT' ? 'Link timeout' : 'Broken link'}: ${failure.url.slice(0, 80)}`,
            description: `Link check failed for ${failure.url} — ${statusDesc}`,
            filePath: filePath.replace(`${SCAN_TARGET}/`, ''),
            lineNumber: null,
            columnNumber: null,
            codeSnippet: failure.url,
            cweId: null,
            owaspCategory: null,
            fixAvailable: false,
            fixDescription: ruleId === 'LYCHEE-TIMEOUT'
              ? 'The linked resource timed out. Verify the URL is still valid or increase timeout.'
              : 'The linked resource returned an error. Update or remove the broken link.',
            metadata: {
              url: failure.url,
              statusCode: failure.status.code ?? null,
              statusText: failure.status.text ?? null,
            },
          });
          count++;
        }
        if (count >= 200) break;
      }
    }

    logger.info({ findingsCount: findings.length }, 'Lychee scan completed');

    return {
      scanner: 'lychee',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Broken link detection',
          'Link timeout detection',
          'Loopback/private address exclusion',
        ],
        scanScope: 'Link validation across documentation and HTML files',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'Default Lychee configuration with loopback/private exclusions',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Lychee scan failed');
    return {
      scanner: 'lychee',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
