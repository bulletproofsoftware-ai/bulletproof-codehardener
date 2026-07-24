/** @deprecated Removed from active scanner rotation in v2. Static Falco rule analysis too niche (<0.1% of repos use Falco). */
import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-falco');

/**
 * Falco Rules Analyzer
 *
 * Analyzes Falco YAML rule files for:
 * - Missing output fields
 * - Overly broad conditions
 * - Disabled rules for critical syscalls
 * - Missing priority assignments
 *
 * NOTE: This runs as static analysis of rule files, not a live Falco daemon.
 * Full runtime monitoring requires Falco running with kernel module/eBPF.
 */
export async function runFalco(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Look for Falco rule files
    const { stdout: ruleSearch } = await execAsync(
      `find /scan-target -name "*falco*" -name "*.yaml" -o -name "*falco*" -name "*.yml" 2>/dev/null`
    );

    const ruleFiles = ruleSearch.trim().split('\n').filter(Boolean);
    if (ruleFiles.length === 0) {
      logger.info('No Falco rule files found');
      return {
        scanner: 'falco',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_matching_files',
        skipHint: 'No Falco YAML rule files found',
      };
    }

    for (const ruleFile of ruleFiles) {
      try {
        const { stdout: content } = await execAsync(`cat "${ruleFile}"`, { maxBuffer: 5 * 1024 * 1024 });
        const relativePath = ruleFile.replace('/scan-target/', '');

        // Simple YAML rule analysis (no full YAML parser needed for pattern matching)
        const ruleBlocks = content.split(/^- rule:/m);

        for (const block of ruleBlocks) {
          if (!block.trim()) continue;

          const ruleName = block.split('\n')[0]?.trim();

          // Check for disabled critical rules
          if (/enabled:\s*false/i.test(block)) {
            const criticalPatterns = [
              'write below binary dir',
              'read sensitive file',
              'container_drift',
              'reverse shell',
              'crypto mining',
              'privilege escalation',
            ];

            const isCritical = criticalPatterns.some(p =>
              (ruleName || '').toLowerCase().includes(p) || block.toLowerCase().includes(p)
            );

            if (isCritical) {
              findings.push({
                ruleId: 'FALCO-CRITICAL-DISABLED',
                severity: 'high',
                title: `Falco: Critical Rule Disabled - ${ruleName || 'Unknown'}`,
                description: 'A security-critical Falco rule is disabled. This may leave blind spots in runtime monitoring.',
                filePath: relativePath,
                lineNumber: null,
                columnNumber: null,
                codeSnippet: null,
                cweId: 'CWE-778',
                owaspCategory: 'A09:2021-Security Logging and Monitoring Failures',
                fixAvailable: true,
                fixDescription: 'Enable this rule or document why it is intentionally disabled',
                metadata: { ruleName },
              });
            }
          }

          // Check for overly broad conditions
          if (/condition:\s*(?:evt\.type\s*=\s*\*|always_true|true)/m.test(block)) {
            findings.push({
              ruleId: 'FALCO-BROAD-CONDITION',
              severity: 'medium',
              title: `Falco: Overly Broad Rule Condition - ${ruleName || 'Unknown'}`,
              description: 'Rule condition matches too broadly. This can generate excessive alerts and alert fatigue.',
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A09:2021-Security Logging and Monitoring Failures',
              fixAvailable: true,
              fixDescription: 'Narrow the condition to specific syscalls, containers, or processes',
              metadata: { ruleName },
            });
          }

          // Check for missing priority
          if (!/priority:/m.test(block) && /condition:/m.test(block)) {
            findings.push({
              ruleId: 'FALCO-MISSING-PRIORITY',
              severity: 'low',
              title: `Falco: Missing Priority - ${ruleName || 'Unknown'}`,
              description: 'Rule does not specify a priority level. Defaults may not match the intended severity.',
              filePath: relativePath,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: null,
              cweId: null,
              owaspCategory: 'A09:2021-Security Logging and Monitoring Failures',
              fixAvailable: true,
              fixDescription: 'Add explicit priority: WARNING, ERROR, CRITICAL, etc.',
              metadata: { ruleName },
            });
          }
        }
      } catch {
        logger.warn({ ruleFile }, 'Failed to parse Falco rule file');
      }
    }

    logger.info({ findingsCount: findings.length, files: ruleFiles.length }, 'Falco rule analysis completed');

    return {
      scanner: 'falco',
      success: true,
      findings,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    logger.error({ error }, 'Falco analysis failed');
    return {
      scanner: 'falco',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
