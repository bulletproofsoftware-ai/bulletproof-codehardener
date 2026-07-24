import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-phpstan');

const SCAN_TARGET = '/scan-target';

interface PhpstanMessage {
  message: string;
  line: number;
  ignorable: boolean;
}

interface PhpstanFileEntry {
  errors: number;
  messages: PhpstanMessage[];
}

interface PhpstanResult {
  totals: {
    errors: number;
    file_errors: number;
  };
  files: Record<string, PhpstanFileEntry>;
}

export async function runPhpstan(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for PHP files in the project
    const { stdout: phpCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 -name "*.php" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | head -1`,
      { maxBuffer: 1024 * 1024, timeout: 10000 }
    );

    if (!phpCheck.trim()) {
      return {
        scanner: 'phpstan',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .php files found — PHPStan requires a PHP project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No PHP files found',
      };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && phpstan analyse --error-format json --no-progress --level 5 . 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
    );

    if (!stdout.trim()) {
      return {
        scanner: 'phpstan',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No output from PHPStan',
      };
    }

    let result: PhpstanResult;
    try {
      result = JSON.parse(stdout.trim());
    } catch {
      logger.warn('Failed to parse PHPStan JSON output');
      return {
        scanner: 'phpstan',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: stdout.slice(0, 5000),
      };
    }

    let count = 0;
    for (const [filePath, fileEntry] of Object.entries(result.files || {})) {
      for (const msg of fileEntry.messages || []) {
        if (count >= 200) break;

        const cleanPath = filePath.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
        findings.push({
          ruleId: 'PHPSTAN-ERROR',
          severity: 'medium',
          title: `PHPStan: ${msg.message.slice(0, 100)}`,
          description: msg.message,
          filePath: cleanPath || null,
          lineNumber: msg.line || null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Fix the PHP type/logic error reported by PHPStan at level 5.`,
          metadata: {
            ignorable: msg.ignorable,
          },
        });
        count++;
      }
      if (count >= 200) break;
    }

    const filesAnalyzed = Object.keys(result.files || {}).length;

    logger.info({ findingsCount: findings.length }, 'PHPStan scan completed');

    return {
      scanner: 'phpstan',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        filesAnalyzed: filesAnalyzed || undefined,
        checksPerformed: [
          'Type inference and checking',
          'Dead code detection',
          'Undefined variable detection',
          'Method call validation',
          'Return type verification',
          'Missing property type detection',
        ],
        scanScope: `PHP static analysis of ${filesAnalyzed} file(s) at level 5`,
        configuration: existsSync(`${SCAN_TARGET}/phpstan.neon`)
          ? 'Project phpstan.neon configuration'
          : 'Default configuration at level 5',
      },
    };
  } catch (error) {
    logger.error({ error }, 'PHPStan scan failed');
    return {
      scanner: 'phpstan',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
