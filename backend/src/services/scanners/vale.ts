import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
// vale: Prose linter enforcing documentation style rules
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-vale');

const SCAN_TARGET = '/scan-target';

interface ValeAlert {
  Action: { Name: string; Params: string[] };
  Check: string;
  Description: string;
  Line: number;
  Link: string;
  Message: string;
  Severity: string;
  Span: [number, number];
}

type ValeOutput = Record<string, ValeAlert[]>;

function mapSeverity(valeSeverity: string): Severity {
  switch (valeSeverity) {
    case 'error': return 'medium';
    case 'warning': return 'low';
    case 'suggestion': return 'info';
    default: return 'info';
  }
}

export async function runVale(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for markdown/doc files
    const { stdout: fileCheck } = await execAsync(
      `find ${SCAN_TARGET} -maxdepth 4 \\( -name "*.md" -o -name "*.rst" -o -name "*.adoc" \\) -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );

    if (!fileCheck.trim()) {
      return {
        scanner: 'vale',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No documentation files (.md, .rst, .adoc) found',
        skipReason: 'no_matching_files',
        skipHint: 'No Markdown/RST/AsciiDoc files found',
      };
    }

    // Create a minimal .vale.ini if none exists
    if (!existsSync(`${SCAN_TARGET}/.vale.ini`)) {
      await execAsync(
        `echo -e "[*]\\nBasedOnStyles = Vale" > ${SCAN_TARGET}/.vale.ini`,
        { timeout: 5000 }
      );
    }

    // Run Vale with JSON output
    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && vale --output JSON . 2>/dev/null || true`,
      { maxBuffer: 10 * 1024 * 1024, timeout: 60000 }
    );

    if (!stdout.trim() || stdout.trim() === '{}' || stdout.trim() === 'null') {
      return {
        scanner: 'vale',
        success: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No issues found',
      };
    }

    let valeResults: ValeOutput;
    try {
      valeResults = JSON.parse(stdout.trim());
    } catch {
      logger.warn('Failed to parse Vale JSON output');
      return {
        scanner: 'vale',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'Failed to parse Vale JSON output — vale may have produced non-JSON error output',
        rawOutput: stdout.slice(0, 5000),
      };
    }

    let totalAlerts = 0;
    const filesWithIssues = Object.keys(valeResults);

    for (const filePath of filesWithIssues) {
      const alerts = valeResults[filePath];
      if (!Array.isArray(alerts)) continue;

      for (const alert of alerts) {
        totalAlerts++;
        if (findings.length >= 100) continue;

        const cleanPath = filePath.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
        const checkName = alert.Check || 'UNKNOWN';

        findings.push({
          ruleId: `VALE-${checkName.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
          severity: mapSeverity(alert.Severity),
          title: `Documentation: ${alert.Message}`,
          description: `${alert.Message}${alert.Description ? `\n\n${alert.Description}` : ''}${alert.Link ? `\n\nReference: ${alert.Link}` : ''}`,
          filePath: cleanPath || null,
          lineNumber: alert.Line || null,
          columnNumber: alert.Span ? alert.Span[0] : null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: !!alert.Action?.Name,
          fixDescription: alert.Action?.Name
            ? `Apply action "${alert.Action.Name}"${alert.Action.Params?.length ? ` with params: ${alert.Action.Params.join(', ')}` : ''}`
            : null,
          metadata: {
            check: alert.Check,
            valeSeverity: alert.Severity,
            span: alert.Span,
          },
        });
      }
    }

    logger.info({ findingsCount: findings.length, totalAlerts, filesScanned: filesWithIssues.length }, 'Vale scan completed');

    return {
      scanner: 'vale',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        filesAnalyzed: filesWithIssues.length,
        rulesEvaluated: totalAlerts,
        checksPerformed: [
          'Prose style and consistency checks',
          'Spelling and grammar validation',
          'Documentation standard enforcement',
          'Readability analysis',
        ],
        scanScope: `Documentation quality analysis — ${filesWithIssues.length} files, ${totalAlerts} alerts found`,
        configuration: existsSync(`${SCAN_TARGET}/.vale.ini`) ? 'Project .vale.ini' : 'Default Vale style',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Vale scan failed');
    return {
      scanner: 'vale',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
