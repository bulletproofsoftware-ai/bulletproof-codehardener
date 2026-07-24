import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-typos');

const SCAN_TARGET = '/scan-target';

interface TyposResult {
  type?: string;
  path: string;
  line_num: number;
  byte_offset: number;
  typo: string;
  corrections: string[];
  context?: {
    kind: string;
    data: string;
  };
}

export async function runTypos(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && typos --format json . 2>/dev/null || true`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 60000 }
    );

    if (!stdout.trim()) {
      return { scanner: 'typos', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No typos found' };
    }

    const results: TyposResult[] = stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean) as TyposResult[];

    for (const entry of results.slice(0, 100)) {
      const cleanPath = (entry.path || '').replace(`${SCAN_TARGET}/`, '').replace(/^\.\//, '');
      const corrections = entry.corrections.length > 0 ? entry.corrections.join(', ') : 'unknown';

      findings.push({
        ruleId: 'TYPOS-SPELLING',
        severity: 'info',
        title: `Typo: "${entry.typo}" should be "${corrections}"`,
        description: `Found typo "${entry.typo}" in ${entry.context?.kind || entry.type || 'source'}. Suggested correction${entry.corrections.length > 1 ? 's' : ''}: ${corrections}.`,
        filePath: cleanPath || null,
        lineNumber: entry.line_num || null,
        columnNumber: null,
        codeSnippet: entry.context?.data || null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: true,
        fixDescription: `Replace "${entry.typo}" with "${corrections}".`,
        metadata: {
          typo: entry.typo,
          corrections: entry.corrections,
          contextKind: entry.context?.kind || entry.type,
          byteOffset: entry.byte_offset,
        },
      });
    }

    logger.info({ findingsCount: findings.length }, 'typos scan completed');
    return {
      scanner: 'typos', success: true, findings, duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        checksPerformed: ['Source code spelling analysis', 'Identifier typo detection', 'Comment typo detection', 'String literal typo detection'],
        scanScope: 'All files in project directory',
      },
    };
  } catch (error) {
    logger.error({ error }, 'typos scan failed');
    return { scanner: 'typos', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
