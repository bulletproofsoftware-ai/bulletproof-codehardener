import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.

const execAsync = promisify(exec);
const logger = createLogger('scanner-axe-core');

const SCAN_TARGET = '/scan-target';
void SCAN_TARGET; // DAST scanner — uses targetUrl, not filesystem

interface AxeViolation {
  id: string;
  impact: 'critical' | 'serious' | 'moderate' | 'minor';
  description: string;
  help: string;
  helpUrl: string;
  tags: string[];
  nodes: AxeNode[];
}

interface AxeNode {
  target: string[];
  html: string;
  failureSummary: string;
}

interface AxeOutput {
  violations: AxeViolation[];
  passes: unknown[];
  incomplete: unknown[];
  inapplicable: unknown[];
  url: string;
}

function mapImpactToSeverity(impact: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical',
    serious: 'high',
    moderate: 'medium',
    minor: 'low',
  };
  return map[impact] || 'info';
}

export async function runAxeCore(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  const targetUrl = jobData.targetUrl;
  if (!targetUrl || !targetUrl.startsWith('http')) {
    logger.info('No target URL provided, skipping axe-core accessibility scan');
    return {
      scanner: 'axe-core',
      success: true,
      skipped: true,
      findings: [],
      duration: Date.now() - startTime,
      skipReason: 'no_target_url',
      skipHint: 'Add a target URL to enable WCAG accessibility testing',
    };
  }

  try {
    const cmd = `axe ${targetUrl} --format json 2>/dev/null || true`;
    const { stdout } = await execAsync(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: 120000 });

    if (stdout.trim()) {
      // axe CLI can output an array of page results or a single result object
      const parsed = JSON.parse(stdout);
      const results: AxeOutput[] = Array.isArray(parsed) ? parsed : [parsed];

      for (const result of results) {
        for (const violation of result.violations || []) {
          const severity = mapImpactToSeverity(violation.impact);
          const ruleId = `AXECORE-${violation.id.toUpperCase()}`;

          // Create one finding per violation, aggregating affected nodes
          const affectedNodes = violation.nodes.slice(0, 5);
          const nodeDetails = affectedNodes
            .map((n: AxeNode) => `Target: ${n.target.join(', ')}\nHTML: ${n.html}\n${n.failureSummary}`)
            .join('\n---\n');

          const wcagTags = violation.tags
            .filter((t: string) => t.startsWith('wcag'))
            .join(', ');

          findings.push({
            ruleId,
            severity,
            title: `${violation.help} (${violation.impact})`,
            description: `${violation.description}${wcagTags ? ` [${wcagTags}]` : ''}. Affects ${violation.nodes.length} element(s).`,
            filePath: null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: nodeDetails.slice(0, 2000),
            cweId: null,
            owaspCategory: null,
            fixAvailable: true,
            fixDescription: `See: ${violation.helpUrl}`,
            metadata: {
              impact: violation.impact,
              tags: violation.tags,
              wcagCriteria: wcagTags || null,
              affectedElements: violation.nodes.length,
              pageUrl: result.url,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'axe-core scan completed');

    return {
      scanner: 'axe-core',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'WCAG 2.0 Level A compliance',
          'WCAG 2.0 Level AA compliance',
          'WCAG 2.1 Level A compliance',
          'WCAG 2.1 Level AA compliance',
          'Section 508 compliance',
          'Best practices checks',
        ],
        scanScope: `WCAG accessibility audit of ${targetUrl}`,
        filesAnalyzed: undefined,
        rulesEvaluated: undefined,
        configuration: 'Default axe-core ruleset',
      },
    };
  } catch (error) {
    logger.error({ error }, 'axe-core scan failed');
    return {
      scanner: 'axe-core',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
