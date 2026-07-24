import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-hadolint');

const SCAN_TARGET = '/scan-target';

interface HadolintResult {
  line: number;
  code: string;
  message: string;
  column: number;
  file: string;
  level: string;
}

function mapSeverity(level: string): Severity {
  const map: Record<string, Severity> = {
    error: 'high',
    warning: 'medium',
    info: 'info',
    style: 'info',
  };
  return map[level.toLowerCase()] || 'info';
}

export async function runHadolint(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Find Dockerfiles
    const { stdout: dockerfiles } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 -name "Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null`,
      { timeout: 5000 }
    ).catch(() => ({ stdout: '' }));

    const dockerfileList = dockerfiles.trim().split('\n').filter(f => f.trim());

    if (dockerfileList.length === 0) {
      return {
        scanner: 'hadolint',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No Dockerfile found — Hadolint lints Dockerfiles for best practices',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Dockerfiles found',
      };
    }

    let rawOutput = '';

    for (const dockerfile of dockerfileList) {
      const relPath = dockerfile.replace(`${SCAN_TARGET}/`, '');
      try {
        const { stdout } = await execAsync(
          `hadolint --format json "${dockerfile}" 2>/dev/null || true`,
          { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
        );

        rawOutput += `--- ${relPath} ---\n${stdout}\n`;

        if (!stdout.trim() || stdout.trim() === '[]') continue;

        const results: HadolintResult[] = JSON.parse(stdout);
        for (const result of results) {
          findings.push({
            ruleId: result.code,
            severity: mapSeverity(result.level),
            title: `${result.code}: ${result.message.slice(0, 100)}`,
            description: result.message,
            filePath: relPath,
            lineNumber: result.line,
            columnNumber: result.column || null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: true,
            fixDescription: `Address Hadolint rule ${result.code}. See https://github.com/hadolint/hadolint/wiki/${result.code}`,
            metadata: { level: result.level, rule: result.code },
          });
        }
      } catch (err) {
        logger.warn({ error: err, file: relPath }, 'Hadolint failed on file');
      }
    }

    logger.info({ findingsCount: findings.length, dockerfiles: dockerfileList.length }, 'Hadolint scan completed');

    return {
      scanner: 'hadolint',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput,
      evidence: {
        checksPerformed: [
          'Dockerfile instruction ordering',
          'Base image pinning',
          'Package manager best practices',
          'Shell best practices (ShellCheck integration)',
          'Layer optimization',
          'Security anti-pattern detection',
        ],
        scanScope: `Dockerfile best-practice linting of ${dockerfileList.length} file(s)`,
        filesAnalyzed: dockerfileList.length,
        configuration: 'Default Hadolint rules',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Hadolint scan failed');
    return {
      scanner: 'hadolint',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
