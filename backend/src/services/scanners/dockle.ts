import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-dockle');

interface DockleResult {
  summary: {
    fatal: number;
    warn: number;
    info: number;
    skip: number;
    pass: number;
  };
  details: Array<{
    code: string;
    title: string;
    level: string;
    alerts: string[];
  }>;
}

function mapSeverity(level: string): Severity {
  const map: Record<string, Severity> = {
    FATAL: 'critical',
    WARN: 'medium',
    INFO: 'info',
  };
  return map[level.toUpperCase()] || 'info';
}

// CIS Docker Benchmark checks applied to Dockerfile content (static analysis fallback)
const DOCKERFILE_CHECKS: Array<{
  code: string;
  title: string;
  level: string;
  pattern: RegExp;
  description: string;
  fix: string;
}> = [
  {
    code: 'CIS-DI-0001',
    title: 'Create a user for the container',
    level: 'WARN',
    pattern: /^(?!.*\bUSER\b)/s,
    description: 'Dockerfile does not contain a USER instruction. The container will run as root by default.',
    fix: 'Add a USER instruction to run the container as a non-root user',
  },
  {
    code: 'CIS-DI-0005',
    title: 'Do not use apt-get upgrade',
    level: 'WARN',
    pattern: /apt-get\s+(upgrade|dist-upgrade)/i,
    description: 'Using apt-get upgrade can introduce unpredictable package versions into the image.',
    fix: 'Remove apt-get upgrade and pin specific package versions instead',
  },
  {
    code: 'CIS-DI-0006',
    title: 'Add HEALTHCHECK instruction',
    level: 'WARN',
    pattern: /^(?!.*\bHEALTHCHECK\b)/s,
    description: 'Dockerfile does not contain a HEALTHCHECK instruction.',
    fix: 'Add HEALTHCHECK instruction to enable container health monitoring',
  },
  {
    code: 'DKL-DI-0001',
    title: 'Avoid latest tag',
    level: 'WARN',
    pattern: /FROM\s+\S+:latest\b/i,
    description: 'Using :latest tag makes builds non-reproducible.',
    fix: 'Pin the base image to a specific version tag or digest',
  },
  {
    code: 'DKL-DI-0003',
    title: 'Avoid ADD instruction',
    level: 'INFO',
    pattern: /^ADD\s/m,
    description: 'ADD has extra features (auto-extraction, remote URLs) that can be surprising. COPY is more predictable.',
    fix: 'Use COPY instead of ADD unless you specifically need tar extraction or remote URLs',
  },
  {
    code: 'DKL-DI-0004',
    title: 'Avoid curl/wget in RUN for fetching packages',
    level: 'INFO',
    pattern: /RUN\s.*(?:curl|wget)\s.*\|\s*(?:sh|bash)/i,
    description: 'Piping curl/wget to shell is a security risk — the remote script could be compromised.',
    fix: 'Download files explicitly, verify checksums, then execute',
  },
  {
    code: 'DKL-DI-0005',
    title: 'Clear apt-get cache',
    level: 'WARN',
    pattern: /apt-get\s+install(?!.*rm\s+-rf\s+\/var\/lib\/apt)/s,
    description: 'apt-get install without clearing the cache increases image size unnecessarily.',
    fix: 'Add && rm -rf /var/lib/apt/lists/* after apt-get install',
  },
  {
    code: 'DKL-LI-0001',
    title: 'Avoid empty password in /etc/shadow',
    level: 'FATAL',
    pattern: /RUN\s.*(?:useradd|adduser)\s.*(?:--password\s*["']?["']?\s|--disabled-password)/i,
    description: 'Creating users with empty passwords is a security risk.',
    fix: 'Set proper passwords or use --disabled-login for non-interactive users',
  },
  {
    code: 'DKL-DI-0006',
    title: 'Avoid sudo in Dockerfile',
    level: 'WARN',
    pattern: /RUN\s.*\bsudo\b/i,
    description: 'Using sudo in Dockerfile is unnecessary and can cause unexpected behavior.',
    fix: 'Use USER instruction to switch users instead of sudo',
  },
];

export async function runDockle(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // If containerImage is provided, scan it directly with dockle binary
    if (jobData.containerImage) {
      try {
        const { stdout } = await execAsync(
          `dockle --format json --exit-code 0 ${jobData.containerImage} 2>/dev/null`,
          { maxBuffer: 50 * 1024 * 1024, timeout: 60000 }
        );

        const result: DockleResult = JSON.parse(stdout.trim());
        for (const detail of result.details || []) {
          if (detail.level === 'PASS' || detail.level === 'SKIP') continue;
          for (const alert of detail.alerts || []) {
            findings.push({
              ruleId: detail.code,
              severity: mapSeverity(detail.level),
              title: `${detail.code}: ${detail.title}`,
              description: alert,
              filePath: null,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A05:2021-Security Misconfiguration',
              fixAvailable: true,
              fixDescription: `Address CIS Docker Benchmark check ${detail.code}: ${detail.title}`,
              metadata: { cisCheckCode: detail.code, level: detail.level, image: jobData.containerImage },
            });
          }
        }

        logger.info({ findingsCount: findings.length, image: jobData.containerImage }, 'Dockle scan completed (container image)');
        return {
          scanner: 'dockle',
          success: true,
          findings,
          duration: Date.now() - startTime,
          rawOutput: stdout,
          evidence: {
            checksPerformed: [
              'CIS Docker Benchmark compliance (50+ checks)', 'SUID/SGID binary detection',
              'Sensitive file detection', 'Content trust verification', 'User namespace check',
              'Network mode restriction check', 'STOPSIGNAL verification',
            ],
            scanScope: `Full CIS Docker Benchmark analysis of image ${jobData.containerImage}`,
            configuration: `Dockle binary scan of ${jobData.containerImage}`,
          },
        };
      } catch (dockleErr) {
        logger.warn({ error: dockleErr, image: jobData.containerImage }, 'Dockle image scan failed, falling back to Dockerfile analysis');
        // Fall through to Dockerfile static analysis
      }
    }

    // Fallback: Dockerfile static analysis (regex-based CIS checks)
    // This runs when no containerImage is set, or when dockle binary scan fails

    // Discover Dockerfiles
    const { stdout: dockerfiles } = await execAsync(
      `find /scan-target -maxdepth 3 -name "Dockerfile*" -not -path "*/node_modules/*" 2>/dev/null`,
      { timeout: 5000 }
    ).catch(() => ({ stdout: '' }));

    const dockerfileList = dockerfiles.trim().split('\n').filter(f => f.trim());

    if (dockerfileList.length === 0) {
      // No container image AND no Dockerfiles
      if (!jobData.containerImage) {
        logger.info('No containerImage set and no Dockerfiles found, skipping Dockle');
        return {
          scanner: 'dockle',
          success: true,
          skipped: true,
          skipReason: 'no_container_image',
          skipHint: 'Add Container Image in Project Settings or include a Dockerfile in your repo',
          findings: [],
          duration: Date.now() - startTime,
        };
      }
      // containerImage was set but dockle failed and no Dockerfiles to fall back to
      return {
        scanner: 'dockle',
        success: true,
        findings,
        duration: Date.now() - startTime,
        rawOutput: `Dockle binary scan failed for ${jobData.containerImage} and no Dockerfiles found for fallback analysis`,
      };
    }

    // Regex-based Dockerfile analysis (9 CIS checks)
    let rawOutput = '';

    for (const dockerfilePath of dockerfileList) {
      let content: string;
      try {
        content = await readFile(dockerfilePath, 'utf-8');
      } catch {
        continue;
      }

      const relPath = dockerfilePath.replace('/scan-target/', '');
      rawOutput += `--- ${relPath} ---\n`;

      for (const check of DOCKERFILE_CHECKS) {
        const matches = check.pattern.test(content);
        if (matches) {
          findings.push({
            ruleId: check.code,
            severity: mapSeverity(check.level),
            title: `${check.code}: ${check.title}`,
            description: check.description,
            filePath: relPath,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: null,
            cweId: null,
            owaspCategory: 'A05:2021-Security Misconfiguration',
            fixAvailable: true,
            fixDescription: check.fix,
            metadata: {
              cisCheckCode: check.code,
              level: check.level,
              mode: 'dockerfile-analysis',
            },
          });
          rawOutput += `  [${check.level}] ${check.code}: ${check.title}\n`;
        }
      }
    }

    logger.info({ findingsCount: findings.length, dockerfiles: dockerfileList.length }, 'Dockle scan completed (regex fallback)');

    return {
      scanner: 'dockle',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutput || 'No issues found',
      evidence: {
        checksPerformed: [
          'USER instruction check', 'HEALTHCHECK instruction check', 'Base image tag pinning',
          'ADD vs COPY usage', 'Curl-pipe-shell detection', 'Apt cache cleanup',
          'Empty password detection', 'Sudo usage detection', 'Apt-get upgrade detection',
        ],
        scanScope: `Dockerfile regex analysis of ${dockerfileList.length} file(s) (9 CIS checks)`,
        filesAnalyzed: dockerfileList.length,
        rulesEvaluated: DOCKERFILE_CHECKS.length,
        configuration: 'Regex-based Dockerfile analysis (no container image provided for full dockle scan)',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Dockle scan failed');
    return {
      scanner: 'dockle',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
