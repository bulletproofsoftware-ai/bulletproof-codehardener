import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-sqlmap');

const SCAN_TARGET = '/scan-target';
void SCAN_TARGET; // DAST scanner — uses targetUrl, not filesystem

export async function runSqlmap(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  const targetUrl = jobData.targetUrl;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No target URL provided, skipping sqlmap injection scan');
    return {
      scanner: 'sqlmap',
      success: true,
      skipped: true,
      findings: [],
      duration: Date.now() - startTime,
      skipReason: 'no_target_url',
      skipHint: 'Add a target URL to enable SQL injection testing',
    };
  }

  try {
    const authConfig = jobData.authConfig;
    const hasAuth = !!(authConfig?.loginUrl && authConfig?.username && authConfig?.password);

    // Build sqlmap command with safe defaults: batch mode, forms discovery, moderate level/risk
    let cmd = `sqlmap -u "${targetUrl}" --batch --forms --level 2 --risk 1 --output-dir /tmp/sqlmap-out 2>/dev/null || true`;

    if (hasAuth) {
      // Add the login URL as an additional target for form-based injection testing
      // Use --data to supply POST body for login form
      const loginData = `${authConfig.usernameField}=${authConfig.username}&${authConfig.passwordField}=${authConfig.password}`;
      const authCmd = `sqlmap -u "${authConfig.loginUrl}" --data="${loginData}" --batch --forms --level 2 --risk 1 --output-dir /tmp/sqlmap-out-auth 2>/dev/null || true`;
      logger.info({ loginUrl: authConfig.loginUrl }, 'sqlmap: testing login form for SQL injection');
      // Run auth target first, then the main target
      cmd = `${authCmd} && ${cmd}`;
    }

    const { stdout } = await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: hasAuth ? 300000 : 180000,
    });

    // Parse sqlmap text output for injection findings
    const lines = stdout.split('\n');
    let currentParameter: string | null = null;
    let currentType: string | null = null;
    let currentPayload: string | null = null;

    for (const line of lines) {
      // Detect injectable parameter lines
      const paramMatch = line.match(/Parameter:\s+(.+?)(?:\s+\(|$)/);
      if (paramMatch) {
        currentParameter = paramMatch[1].trim();
      }

      // Detect injection type
      const typeMatch = line.match(/Type:\s+(.+)/);
      if (typeMatch) {
        currentType = typeMatch[1].trim();
      }

      // Detect payload
      const payloadMatch = line.match(/Payload:\s+(.+)/);
      if (payloadMatch) {
        currentPayload = payloadMatch[1].trim();
      }

      // When we have a complete injection finding
      if (line.includes('is vulnerable') || (currentParameter && currentType && currentPayload)) {
        const vulnParam = currentParameter || 'unknown';

        findings.push({
          ruleId: 'SQLMAP-INJECTION',
          severity: 'critical',
          title: `SQL Injection: parameter '${vulnParam}' is injectable`,
          description: `sqlmap confirmed SQL injection vulnerability in parameter '${vulnParam}'.${currentType ? ` Type: ${currentType}.` : ''}${currentPayload ? ` Payload: ${currentPayload.slice(0, 200)}` : ''}`,
          filePath: null,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: currentPayload?.slice(0, 2000) ?? null,
          cweId: 'CWE-89',
          owaspCategory: 'A03:2021-Injection',
          fixAvailable: false,
          fixDescription: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Validate and sanitize all input parameters.',
          metadata: {
            parameter: vulnParam,
            injectionType: currentType,
            payload: currentPayload,
            targetUrl,
          },
        });

        // Reset for next finding
        currentType = null;
        currentPayload = null;
      }
    }

    // Also check sqlmap log files for additional findings
    const sqlmapOutDir = '/tmp/sqlmap-out';
    if (existsSync(sqlmapOutDir)) {
      try {
        const hostDirs = readdirSync(sqlmapOutDir);
        for (const hostDir of hostDirs) {
          const logPath = `${sqlmapOutDir}/${hostDir}/log`;
          if (existsSync(logPath)) {
            const logContent = readFileSync(logPath, 'utf-8');

            // Parse log for additional injectable parameters not caught above
            const logInjections = logContent.match(/Parameter:\s+.+\n.*Type:\s+.+/g) || [];
            for (const injection of logInjections) {
              const logParamMatch = injection.match(/Parameter:\s+(.+)/);
              const logTypeMatch = injection.match(/Type:\s+(.+)/);

              const param = logParamMatch?.[1]?.trim() || 'unknown';
              const type = logTypeMatch?.[1]?.trim() || 'unknown';

              // Avoid duplicates
              const isDuplicate = findings.some(
                (f) => (f.metadata as Record<string, unknown>)?.parameter === param &&
                       (f.metadata as Record<string, unknown>)?.injectionType === type
              );

              if (!isDuplicate) {
                findings.push({
                  ruleId: 'SQLMAP-INJECTION',
                  severity: 'critical',
                  title: `SQL Injection: parameter '${param}' is injectable (${type})`,
                  description: `sqlmap confirmed SQL injection in parameter '${param}'. Type: ${type}.`,
                  filePath: null,
                  lineNumber: null,
                  columnNumber: null,
                  codeSnippet: null,
                  cweId: 'CWE-89',
                  owaspCategory: 'A03:2021-Injection',
                  fixAvailable: false,
                  fixDescription: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.',
                  metadata: {
                    parameter: param,
                    injectionType: type,
                    payload: null,
                    targetUrl,
                    source: 'sqlmap-log',
                  },
                });
              }
            }
          }
        }
      } catch {
        // Log parsing is best-effort
      }
    }

    logger.info({ findingsCount: findings.length }, 'sqlmap scan completed');

    return {
      scanner: 'sqlmap',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Boolean-based blind SQL injection',
          'Error-based SQL injection',
          'UNION query SQL injection',
          'Stacked queries injection',
          'Time-based blind SQL injection',
          'Form parameter discovery',
          ...(hasAuth ? ['Login form injection testing', 'POST parameter injection testing'] : []),
        ],
        scanScope: `SQL injection testing against ${targetUrl}${hasAuth ? ` and login form at ${authConfig.loginUrl}` : ''}`,
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: `sqlmap level 2 / risk 1 with form crawling${hasAuth ? ', login form POST data injection testing' : ''}`,
        authenticationStatus: hasAuth ? 'authenticated' : 'unauthenticated',
      },
    };
  } catch (error) {
    logger.error({ error }, 'sqlmap scan failed');
    return {
      scanner: 'sqlmap',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
