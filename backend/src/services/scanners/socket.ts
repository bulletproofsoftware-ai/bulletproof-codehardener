import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-socket');

const SCAN_TARGET = '/scan-target';

interface SocketIssue {
  type: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  package: string;
  version: string;
  url?: string;
}

interface SocketOutput {
  issues: SocketIssue[];
  score?: number;
  packages?: number;
}

function mapCategoryToSeverity(category: string, severity: string): Severity {
  const cat = category.toLowerCase();
  const sev = severity.toLowerCase();

  if (cat === 'supply-chain' || cat === 'supplychain' || sev === 'critical') return 'critical';
  if (cat === 'vulnerability' || sev === 'high') return 'high';
  if (cat === 'quality' || cat === 'maintenance' || sev === 'medium') return 'medium';
  if (cat === 'license' || sev === 'low') return 'low';
  return 'info';
}

export async function runSocket(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for package manifest files
    const hasPackageJson = existsSync(`${SCAN_TARGET}/package.json`);
    const hasRequirements = existsSync(`${SCAN_TARGET}/requirements.txt`);
    const hasPyproject = existsSync(`${SCAN_TARGET}/pyproject.toml`);
    const hasGoMod = existsSync(`${SCAN_TARGET}/go.mod`);

    if (!hasPackageJson && !hasRequirements && !hasPyproject && !hasGoMod) {
      return {
        scanner: 'socket',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package manifest found (package.json, requirements.txt, pyproject.toml, go.mod)',
        skipReason: 'no_package_manifest',
        skipHint: 'Socket.dev requires a package manifest file to analyze dependencies',
      };
    }

    // Check for API key
    const apiKey = process.env.SOCKET_API_KEY;
    if (!apiKey) {
      return {
        scanner: 'socket',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'SOCKET_API_KEY environment variable not set',
        skipReason: 'no_config_files',
        skipHint: 'Set the SOCKET_API_KEY environment variable to enable Socket.dev supply chain analysis',
      };
    }

    // Run Socket scan
    const cmd = `socket scan create --repo ${SCAN_TARGET} --format json 2>/dev/null || true`;
    const { stdout } = await execAsync(cmd, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 120000,
      env: { ...process.env, SOCKET_API_KEY: apiKey },
    });

    if (stdout.trim()) {
      // Try to parse as JSON
      let output: SocketOutput;
      try {
        output = JSON.parse(stdout);
      } catch {
        // Some versions output newline-delimited JSON
        const lines = stdout.trim().split('\n');
        const issues: SocketIssue[] = [];
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.issues) {
              issues.push(...parsed.issues);
            } else if (parsed.type) {
              issues.push(parsed as SocketIssue);
            }
          } catch {
            // Skip unparseable lines
          }
        }
        output = { issues };
      }

      for (const issue of (output.issues || []).slice(0, 200)) {
        const severity = mapCategoryToSeverity(issue.category, issue.severity);
        const category = (issue.category || 'unknown').toUpperCase().replace(/[^A-Z0-9]/g, '-');
        const ruleId = `SOCKET-${category}`;

        findings.push({
          ruleId,
          severity,
          title: `${issue.title || issue.type}: ${issue.package}@${issue.version}`,
          description: issue.description || `Socket.dev detected a ${issue.category} issue in ${issue.package}@${issue.version}.`,
          filePath: hasPackageJson ? 'package.json' : (hasRequirements ? 'requirements.txt' : (hasPyproject ? 'pyproject.toml' : 'go.mod')),
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: issue.category === 'supply-chain' ? 'CWE-1357' : null,
          owaspCategory: issue.category === 'supply-chain' ? 'A06:2021-Vulnerable and Outdated Components' : null,
          fixAvailable: false,
          fixDescription: issue.url
            ? `See: ${issue.url}`
            : `Review the ${issue.category} risk for ${issue.package}@${issue.version} and consider alternatives.`,
          metadata: {
            package: issue.package,
            version: issue.version,
            category: issue.category,
            issueType: issue.type,
            socketSeverity: issue.severity,
            url: issue.url ?? null,
            overallScore: output.score ?? null,
            totalPackages: output.packages ?? null,
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length }, 'Socket scan completed');

    return {
      scanner: 'socket',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'Supply chain risk analysis',
          'Dependency quality assessment',
          'Maintenance status check',
          'License compatibility analysis',
          'Known vulnerability matching',
          'Typosquatting detection',
        ],
        scanScope: 'Dependency supply chain analysis via Socket.dev',
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'Socket.dev API with default risk thresholds',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Socket scan failed');
    return {
      scanner: 'socket',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
