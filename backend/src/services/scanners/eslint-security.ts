import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import { cweToOwasp } from './cwe-owasp-map.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-eslint-security');

interface ESLintMessage {
  ruleId: string;
  severity: number;
  message: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
}

interface ESLintResult {
  filePath: string;
  messages: ESLintMessage[];
  errorCount: number;
  warningCount: number;
}

function mapSeverity(eslintSeverity: number): Severity {
  // ESLint: 1 = warning, 2 = error
  return eslintSeverity === 2 ? 'high' : 'medium';
}

export async function runESLintSecurity(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Gate: skip if no JS/TS files present
    const { stdout: jsFiles } = await execAsync(
      `find /scan-target -maxdepth 4 \\( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \\) -not -path "*/node_modules/*" -not -path "*/dist/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );
    if (!jsFiles.trim()) {
      return {
        scanner: 'eslint-security',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No JS/TS files found — ESLint Security requires a JavaScript/TypeScript project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No JavaScript/TypeScript files found in project',
      };
    }

    // Use mounted config if available, otherwise create temp config
    const mountedConfig = '/configs/eslint-security.json';
    const configPath = existsSync(mountedConfig) ? mountedConfig : '/tmp/eslint-security-config.json';

    if (!existsSync(mountedConfig)) {
      const config = {
        extends: ['plugin:security/recommended-legacy'],
        plugins: ['security', 'no-unsanitized'],
        rules: {
          'no-unsanitized/method': 'error',
          'no-unsanitized/property': 'error',
        },
        env: {
          browser: true,
          node: true,
          es2022: true,
        },
      };

      await execAsync(`echo '${JSON.stringify(config)}' > ${configPath}`);
    }

    // Run ESLint with security plugins
    const { stdout } = await execAsync(
      `eslint /scan-target --config ${configPath} --format json --ext .js,.jsx,.ts,.tsx 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const results: ESLintResult[] = JSON.parse(stdout);

      for (const file of results) {
        for (const msg of file.messages) {
          if (!msg.ruleId) continue;

          const cweId = getSecurityCWE(msg.ruleId);
          findings.push({
            ruleId: msg.ruleId,
            severity: mapSeverity(msg.severity),
            title: `ESLint Security: ${msg.ruleId}`,
            description: msg.message,
            filePath: file.filePath.replace('/scan-target/', ''),
            lineNumber: msg.line,
            columnNumber: msg.column,
            codeSnippet: null,
            cweId,
            owaspCategory: cweToOwasp(cweId) || 'A03:2021-Injection',
            fixAvailable: true,
            fixDescription: `Review and fix the security issue flagged by ${msg.ruleId}`,
            metadata: {
              endLine: msg.endLine,
              endColumn: msg.endColumn,
            },
          });
        }
      }
    }

    // Extract audit evidence from ESLint results
    const eslintResults: ESLintResult[] = stdout.trim() ? JSON.parse(stdout) : [];
    const totalFilesChecked = eslintResults.length;
    const filesWithIssues = eslintResults.filter(r => r.messages.length > 0).length;

    logger.info({ findingsCount: findings.length, totalFilesChecked }, 'ESLint Security scan completed');

    return {
      scanner: 'eslint-security',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        filesAnalyzed: totalFilesChecked,
        rulesEvaluated: 10, // security/detect-* + no-unsanitized rules
        checksPerformed: [
          'Eval with expression detection', 'Non-literal filesystem access',
          'Non-literal require/import', 'Object injection detection',
          'Timing attack detection', 'Unsafe regex detection',
          'DOM-based XSS (unsanitized methods)', 'DOM-based XSS (unsanitized properties)',
        ],
        scanScope: `JavaScript/TypeScript SAST — ${totalFilesChecked} files checked, ${filesWithIssues} with issues`,
        configuration: existsSync('/configs/eslint-security.json') ? 'Custom eslint-security.json' : 'Default security plugin + no-unsanitized',
      },
    };
  } catch (error) {
    logger.error({ error }, 'ESLint Security scan failed');
    return {
      scanner: 'eslint-security',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getSecurityCWE(ruleId: string): string | null {
  const cweMap: Record<string, string> = {
    'security/detect-eval-with-expression': 'CWE-95',
    'security/detect-non-literal-fs-filename': 'CWE-22',
    'security/detect-non-literal-require': 'CWE-94',
    'security/detect-object-injection': 'CWE-94',
    'security/detect-possible-timing-attacks': 'CWE-208',
    'security/detect-unsafe-regex': 'CWE-1333',
    'no-unsanitized/method': 'CWE-79',
    'no-unsanitized/property': 'CWE-79',
  };
  return cweMap[ruleId] || null;
}
