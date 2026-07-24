import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-pa11y');

interface Pa11yIssue {
  code: string;
  type: 'error' | 'warning' | 'notice';
  typeCode: number;
  message: string;
  context: string;
  selector: string;
  runner: string;
  runnerExtras: Record<string, any>;
}

interface Pa11yResult {
  documentTitle: string;
  pageUrl: string;
  issues: Pa11yIssue[];
}

function mapSeverity(type: string): Severity {
  const map: Record<string, Severity> = {
    'error': 'high',
    'warning': 'medium',
    'notice': 'low',
  };
  return map[type] || 'info';
}

export async function runPa11y(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const targetUrl = jobData.targetUrl;

  if (!targetUrl) {
    // Check for pa11y-ci config
    const { stdout: configCheck } = await execAsync(
      `test -f /scan-target/.pa11yci -o -f /scan-target/.pa11yci.json && echo "exists" || echo "missing"`
    );

    if (configCheck.trim() !== 'exists') {
      logger.info('No target URL or pa11y config found');
      return {
        scanner: 'pa11y',
        success: true,
        skipped: true,
        skipReason: 'no_target_url',
        skipHint: 'Add Application URL in Project Settings to enable accessibility scanning',
        findings: [],
        duration: Date.now() - startTime,
      };
    }
  }

  try {
    let results: Pa11yResult[] = [];
    let rawOutput = '';

    if (targetUrl) {
      // Run pa11y on single URL
      const { stdout } = await execAsync(
        `pa11y "${targetUrl}" --reporter json --standard WCAG2AA 2>/dev/null || echo "[]"`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
      );

      rawOutput = stdout;

      if (stdout.trim() && stdout.trim() !== '[]') {
        const result = JSON.parse(stdout);
        results = Array.isArray(result) ? [{ pageUrl: targetUrl, documentTitle: '', issues: result }] : [result];
      }
    } else {
      // Run pa11y-ci with config
      const outputFile = `/tmp/pa11y-results-${Date.now()}.json`;
      await execAsync(
        `cd /scan-target && pa11y-ci --reporter json > ${outputFile} 2>/dev/null || true`,
        { maxBuffer: 50 * 1024 * 1024, timeout: 300000 }
      );

      const { stdout } = await execAsync(`cat ${outputFile} 2>/dev/null || echo "{}"`);
      rawOutput = stdout;

      if (stdout.trim() && stdout.trim() !== '{}') {
        const ciResult = JSON.parse(stdout);
        if (ciResult.results) {
          results = Object.entries(ciResult.results).map(([url, data]: [string, any]) => ({
            pageUrl: url,
            documentTitle: '',
            issues: data.issues || [],
          }));
        }
      }
    }

    for (const result of results) {
      for (const issue of result.issues || []) {
        findings.push({
          ruleId: issue.code,
          severity: mapSeverity(issue.type),
          title: `Pa11y: ${getWCAGTitle(issue.code)}`,
          description: issue.message,
          filePath: result.pageUrl,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Fix accessibility issue for selector: ${issue.selector}`,
          metadata: {
            wcagCode: issue.code,
            type: issue.type,
            context: issue.context,
            selector: issue.selector,
            runner: issue.runner,
            pageUrl: result.pageUrl,
          },
        });
      }
    }

    // Summarize by type
    const errorCount = findings.filter(f => f.severity === 'high').length;
    const warningCount = findings.filter(f => f.severity === 'medium').length;

    if (errorCount > 10) {
      findings.push({
        ruleId: 'PA11Y-HIGH-ERRORS',
        severity: 'critical',
        title: 'Pa11y: Many Accessibility Errors',
        description: `Found ${errorCount} accessibility errors across scanned pages`,
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: null,
        cweId: null,
        owaspCategory: null,
        fixAvailable: false,
        fixDescription: 'Address accessibility errors to meet WCAG compliance',
        metadata: {
          errorCount,
          warningCount,
        },
      });
    }

    logger.info({ findingsCount: findings.length }, 'Pa11y accessibility test completed');

    return {
      scanner: 'pa11y',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput,
    };
  } catch (error) {
    logger.error({ error }, 'Pa11y accessibility test failed');
    return {
      scanner: 'pa11y',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getWCAGTitle(code: string): string {
  // Map common WCAG codes to readable titles
  const codeMap: Record<string, string> = {
    'WCAG2AA.Principle1.Guideline1_1.1_1_1.H37': 'Missing Image Alt Text',
    'WCAG2AA.Principle1.Guideline1_3.1_3_1.H44.NonExistent': 'Missing Form Label',
    'WCAG2AA.Principle1.Guideline1_4.1_4_3.G18': 'Insufficient Color Contrast',
    'WCAG2AA.Principle2.Guideline2_4.2_4_1.H64.1': 'Missing Frame Title',
    'WCAG2AA.Principle2.Guideline2_4.2_4_4.H77': 'Unclear Link Text',
    'WCAG2AA.Principle4.Guideline4_1.4_1_1.F77': 'Duplicate ID',
    'WCAG2AA.Principle4.Guideline4_1.4_1_2.H91': 'Missing ARIA Role',
  };

  return codeMap[code] || code.split('.').pop() || 'Accessibility Issue';
}
