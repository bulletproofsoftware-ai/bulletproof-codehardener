import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-jscpd');

const SCAN_TARGET = '/scan-target';

interface JscpdDuplicate {
  format: string;
  lines: number;
  tokens: number;
  firstFile: { name: string; start: number; end: number; startLoc: { line: number; column: number } };
  secondFile: { name: string; start: number; end: number; startLoc: { line: number; column: number } };
  fragment: string;
}

interface JscpdReport {
  duplicates: JscpdDuplicate[];
  statistics: { total: { percentage: string; lines: number; sources: number; clones: number } };
}

function percentToSeverity(pct: number): Severity {
  if (pct > 30) return 'high';
  if (pct > 15) return 'medium';
  if (pct > 5) return 'low';
  return 'info';
}

export async function runJscpd(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    await execAsync(
      `cd ${SCAN_TARGET} && jscpd --reporters json --output /tmp/jscpd-out --ignore "**/node_modules/**,**/dist/**,**/.next/**,**/vendor/**" --min-lines 10 . 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
    );

    const reportPath = existsSync('/tmp/jscpd-out/jscpd-report.json') ? '/tmp/jscpd-out/jscpd-report.json' : '/tmp/jscpd-report.json';
    if (!existsSync(reportPath)) {
      return { scanner: 'jscpd', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No jscpd report generated' };
    }

    const raw = await readFile(reportPath, 'utf-8');
    let report: JscpdReport;
    try { report = JSON.parse(raw); } catch {
      return { scanner: 'jscpd', success: true, findings: [], duration: Date.now() - startTime, rawOutput: raw.slice(0, 2000) };
    }

    const totalPct = parseFloat(report.statistics?.total?.percentage || '0');

    for (const dup of (report.duplicates || []).slice(0, 100)) {
      const cleanFirst = (dup.firstFile?.name || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      const cleanSecond = (dup.secondFile?.name || '').replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      findings.push({
        ruleId: 'JSCPD-DUPLICATE',
        severity: percentToSeverity(totalPct),
        title: `Code duplication: ${dup.lines} lines between ${cleanFirst} and ${cleanSecond}`,
        description: `${dup.lines} lines (${dup.tokens} tokens) of duplicated ${dup.format} code.\n` +
          `- ${cleanFirst}:${dup.firstFile?.startLoc?.line || 0}\n- ${cleanSecond}:${dup.secondFile?.startLoc?.line || 0}\n` +
          `Overall duplication: ${totalPct}%`,
        filePath: cleanFirst, lineNumber: dup.firstFile?.startLoc?.line || null, columnNumber: null,
        codeSnippet: dup.fragment?.slice(0, 500) || null,
        cweId: null, owaspCategory: null, fixAvailable: true,
        fixDescription: 'Extract duplicated code into a shared function or module.',
        metadata: { lines: dup.lines, tokens: dup.tokens, format: dup.format, secondFile: cleanSecond, duplicationPct: totalPct },
      });
    }

    logger.info({ findingsCount: findings.length, duplicationPct: totalPct }, 'jscpd scan completed');
    return {
      scanner: 'jscpd', success: true, findings, duration: Date.now() - startTime,
      rawOutput: JSON.stringify(report.statistics),
      evidence: {
        checksPerformed: ['Cross-file copy-paste detection', 'Code clone identification', 'Duplication percentage calculation'],
        scanScope: `All source files (${report.statistics?.total?.sources || 0} files, ${totalPct}% duplication)`,
        configuration: `Min lines: 10, Total clones: ${report.statistics?.total?.clones || 0}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'jscpd scan failed');
    return { scanner: 'jscpd', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
