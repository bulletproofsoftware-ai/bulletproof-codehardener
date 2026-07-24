import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
// This is the standard pattern used by all scanners in this codebase.
const execAsync = promisify(exec);
const logger = createLogger('scanner-scorecard');

const SCAN_TARGET = '/scan-target';

interface ScorecardCheck {
  name: string;
  score: number;
  reason: string;
  details?: string[];
  documentation: { url: string };
}

interface ScorecardReport {
  score: number;
  checks: ScorecardCheck[];
}

function scoreToSeverity(score: number): Severity {
  if (score <= 2) return 'high';
  if (score <= 5) return 'medium';
  if (score <= 7) return 'low';
  return 'info';
}

export async function runScorecard(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!existsSync(`${SCAN_TARGET}/.git`)) {
      return { scanner: 'scorecard', success: true, skipped: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No .git directory — scorecard requires a git repository', skipReason: 'no_git_repo', skipHint: 'Scorecard requires a git repository with a remote origin' };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && scorecard --local . --format json 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
    );

    if (!stdout.trim()) {
      return { scanner: 'scorecard', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No output from scorecard' };
    }

    let report: ScorecardReport;
    try { report = JSON.parse(stdout.trim()); } catch {
      return { scanner: 'scorecard', success: true, findings: [], duration: Date.now() - startTime, rawOutput: stdout.slice(0, 2000) };
    }

    for (const check of (report.checks || [])) {
      if (check.score >= 8) continue;

      findings.push({
        ruleId: `SCORECARD-${check.name.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
        severity: scoreToSeverity(check.score),
        title: `OpenSSF Scorecard: ${check.name} (${check.score}/10)`,
        description: `${check.reason}${check.details?.length ? '\n\nDetails:\n' + check.details.slice(0, 5).join('\n') : ''}`,
        filePath: null, lineNumber: null, columnNumber: null, codeSnippet: null,
        cweId: null, owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
        fixAvailable: true,
        fixDescription: `Improve the ${check.name} score. See: ${check.documentation?.url || 'https://scorecard.dev'}`,
        metadata: { checkName: check.name, score: check.score, maxScore: 10 },
      });
    }

    logger.info({ overallScore: report.score, findingsCount: findings.length }, 'Scorecard scan completed');
    return {
      scanner: 'scorecard', success: true, findings, duration: Date.now() - startTime,
      rawOutput: JSON.stringify({ overallScore: report.score, checksRun: report.checks?.length }),
      evidence: {
        checksPerformed: (report.checks || []).map(c => `${c.name}: ${c.score}/10`),
        scanScope: 'Repository-level supply chain security assessment',
        configuration: `Overall score: ${report.score}/10`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Scorecard scan failed');
    return { scanner: 'scorecard', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
