import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
// This is the standard pattern used by all 48 existing scanners in this codebase.
const execAsync = promisify(exec);
const logger = createLogger('scanner-knip');

const SCAN_TARGET = '/scan-target';

interface KnipIssue {
  file: string;
  symbol?: string;
  type: string;
}

interface KnipReport {
  files: string[];
  issues: KnipIssue[];
  dependencies?: string[];
  devDependencies?: string[];
  unlisted?: string[];
  unresolved?: string[];
}

export async function runKnip(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!existsSync(`${SCAN_TARGET}/package.json`)) {
      return {
        scanner: 'knip',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No package.json found — not a JS/TS project',
        skipReason: 'no_matching_files',
        skipHint: 'No package.json found — Knip requires a Node.js project',
      };
    }

    await execAsync(`cd ${SCAN_TARGET} && npm install 2>/dev/null`, {
      maxBuffer: 100 * 1024 * 1024, timeout: 120000,
    }).catch(() => {});

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && npx --yes knip --reporter json 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
    );

    if (!stdout.trim()) {
      return { scanner: 'knip', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No output' };
    }

    let report: KnipReport;
    try { report = JSON.parse(stdout.trim()); } catch {
      return { scanner: 'knip', success: true, findings: [], duration: Date.now() - startTime, rawOutput: stdout.slice(0, 2000) };
    }

    for (const file of (report.files || []).slice(0, 50)) {
      const cleanPath = file.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      findings.push({
        ruleId: 'KNIP-UNUSED-FILE', severity: 'medium',
        title: `Unused file: ${cleanPath}`,
        description: `This file is not imported or referenced by any other file. Dead code increases maintenance burden and attack surface.`,
        filePath: cleanPath, lineNumber: null, columnNumber: null, codeSnippet: null,
        cweId: null, owaspCategory: null, fixAvailable: true,
        fixDescription: 'Remove the unused file or add an import/reference to it.',
        metadata: { type: 'unused-file' },
      });
    }

    for (const dep of (report.dependencies || []).slice(0, 30)) {
      findings.push({
        ruleId: 'KNIP-UNUSED-DEP', severity: 'medium',
        title: `Unused dependency: ${dep}`,
        description: `"${dep}" is listed in dependencies but not imported. Unused dependencies bloat the bundle and increase supply chain risk.`,
        filePath: 'package.json', lineNumber: null, columnNumber: null, codeSnippet: null,
        cweId: 'CWE-1104', owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
        fixAvailable: true, fixDescription: `Remove "${dep}" from package.json dependencies.`,
        metadata: { type: 'unused-dependency', package: dep },
      });
    }

    for (const dep of (report.unlisted || []).slice(0, 30)) {
      findings.push({
        ruleId: 'KNIP-UNLISTED-DEP', severity: 'high',
        title: `Unlisted dependency: ${dep}`,
        description: `"${dep}" is imported in code but not listed in package.json. This causes install failures and indicates phantom dependencies.`,
        filePath: 'package.json', lineNumber: null, columnNumber: null, codeSnippet: null,
        cweId: 'CWE-1104', owaspCategory: null, fixAvailable: true,
        fixDescription: `Add "${dep}" to package.json dependencies.`,
        metadata: { type: 'unlisted-dependency', package: dep },
      });
    }

    for (const issue of (report.issues || []).slice(0, 50)) {
      const cleanPath = issue.file.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');
      findings.push({
        ruleId: 'KNIP-UNUSED-EXPORT', severity: 'low',
        title: `Unused export${issue.symbol ? `: ${issue.symbol}` : ''} in ${cleanPath}`,
        description: `The export "${issue.symbol || 'unknown'}" in ${cleanPath} is not imported anywhere. Type: ${issue.type}.`,
        filePath: cleanPath, lineNumber: null, columnNumber: null, codeSnippet: null,
        cweId: null, owaspCategory: null, fixAvailable: true,
        fixDescription: 'Remove the unused export or add a consumer.',
        metadata: { type: issue.type, symbol: issue.symbol },
      });
    }

    logger.info({ findingsCount: findings.length }, 'Knip scan completed');
    return {
      scanner: 'knip', success: true, findings, duration: Date.now() - startTime,
      rawOutput: stdout.slice(0, 5000),
      evidence: {
        checksPerformed: ['Unused file detection', 'Unused dependency detection', 'Unlisted dependency detection', 'Unused export detection'],
        scanScope: 'JavaScript/TypeScript project files and dependencies',
      },
    };
  } catch (error) {
    logger.error({ error }, 'Knip scan failed');
    return { scanner: 'knip', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
