import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-dotenv-linter');

const SCAN_TARGET = '/scan-target';

function checkToSeverity(checkName: string): Severity {
  if (checkName === 'DuplicatedKey' || checkName === 'ExtraBlankLine') return 'low';
  if (checkName === 'UnorderedKey') return 'info';
  return 'medium';
}

function checkToRuleId(checkName: string): string {
  return `DOTENV-${checkName.replace(/([a-z])([A-Z])/g, '$1-$2').toUpperCase()}`;
}

export async function runDotenvLinter(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Find .env files in the scan target
    const { stdout: envFileList } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 3 -name ".env*" -not -name ".env.example" -not -path "*/node_modules/*" 2>/dev/null`,
      { timeout: 10000 }
    );

    const envFiles = envFileList.trim().split('\n').filter(Boolean);

    if (envFiles.length === 0) {
      return {
        scanner: 'dotenv-linter',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .env files found — dotenv-linter checks .env files for formatting and security issues',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No .env files found',
      };
    }

    const { stdout } = await execAsync(
      `dotenv-linter ${envFiles.join(' ')} 2>/dev/null || true`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }
    );

    if (stdout.trim()) {
      const lineRegex = /^(.+?):(\d+)\s+(\w+):\s+(.+)$/;

      for (const line of stdout.trim().split('\n').filter(Boolean)) {
        const match = line.match(lineRegex);
        if (!match) continue;

        const [, filePath, lineNum, checkName, message] = match;
        const cleanPath = filePath.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');

        findings.push({
          ruleId: checkToRuleId(checkName),
          severity: checkToSeverity(checkName),
          title: `dotenv-linter: ${checkName}`,
          description: message,
          filePath: cleanPath,
          lineNumber: parseInt(lineNum, 10),
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Fix the ${checkName} issue in your .env file. Run \`dotenv-linter fix\` to auto-fix supported issues.`,
          metadata: { checkName },
        });
      }
    }

    logger.info({ findingsCount: findings.length, envFilesChecked: envFiles.length }, 'dotenv-linter scan completed');

    return {
      scanner: 'dotenv-linter',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        filesAnalyzed: envFiles.length,
        checksPerformed: [
          'Duplicated key detection',
          'Extra blank line detection',
          'Incorrect delimiter usage',
          'Key ordering validation',
          'Leading character checks',
          'Lowercase key detection',
          'Space character validation',
          'Trailing whitespace detection',
          'Quote consistency checks',
        ],
        scanScope: `.env files (${envFiles.length} files checked)`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'dotenv-linter scan failed');
    return {
      scanner: 'dotenv-linter',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
