import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';
import type { Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-pmd');

interface PMDViolation {
  beginline: number;
  begincolumn: number;
  endline: number;
  endcolumn: number;
  description: string;
  rule: string;
  ruleset: string;
  priority: number;
  externalInfoUrl: string;
}

interface PMDFile {
  filename: string;
  violations: PMDViolation[];
}

interface PMDResult {
  formatVersion: number;
  pmdVersion: string;
  timestamp: string;
  files: PMDFile[];
  processingErrors?: any[];
}

function mapSeverity(priority: number): Severity {
  // PMD priority: 1 = highest, 5 = lowest
  if (priority === 1) return 'critical';
  if (priority === 2) return 'high';
  if (priority === 3) return 'medium';
  if (priority === 4) return 'low';
  return 'info';
}

export async function runPMD(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Gate: skip if no Java files present
    const { stdout: javaFiles } = await execAsync(
      `find /scan-target -maxdepth 4 -name "*.java" -not -path "*/node_modules/*" -not -path "*/build/*" 2>/dev/null | head -1`,
      { timeout: 10000 }
    );
    if (!javaFiles.trim()) {
      return {
        scanner: 'pmd',
        success: true,
        skipped: true,
        skipReason: 'no_matching_files',
        skipHint: 'No .java files found — PMD requires a Java project',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'No Java files found in project',
      };
    }

    // Run PMD with security-focused rulesets
    const rulesetFlag = existsSync('/configs/pmd-ruleset.xml')
      ? '-R /configs/pmd-ruleset.xml'
      : '-R category/java/security.xml,category/java/errorprone.xml,category/java/bestpractices.xml,category/ecmascript/errorprone.xml,category/ecmascript/bestpractices.xml';
    const cmd = `pmd check -d /scan-target ${rulesetFlag} -f json --minimum-priority 3 2>/dev/null || true`;
    const { stdout } = await execAsync(
      cmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const result: PMDResult = JSON.parse(stdout);

      for (const file of result.files || []) {
        for (const violation of file.violations || []) {
          findings.push({
            ruleId: violation.rule,
            severity: mapSeverity(violation.priority),
            title: `PMD: ${violation.rule}`,
            description: violation.description,
            filePath: file.filename.replace('/scan-target/', ''),
            lineNumber: violation.beginline,
            columnNumber: violation.begincolumn,
            codeSnippet: null,
            cweId: getPMDCWE(violation.rule),
            owaspCategory: getOWASPCategory(violation.ruleset),
            fixAvailable: true,
            fixDescription: `Review: ${violation.externalInfoUrl}`,
            metadata: {
              ruleset: violation.ruleset,
              endLine: violation.endline,
              endColumn: violation.endcolumn,
              priority: violation.priority,
            },
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'PMD scan completed');

    return {
      scanner: 'pmd',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
    };
  } catch (error) {
    logger.error({ error }, 'PMD scan failed');
    return {
      scanner: 'pmd',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

function getPMDCWE(rule: string): string | null {
  const cweMap: Record<string, string> = {
    'HardCodedCryptoKey': 'CWE-321',
    'InsecureCryptoIv': 'CWE-329',
    'JakartaServletXSSVulnerability': 'CWE-79',
    'JspXss': 'CWE-79',
    'SqlInjection': 'CWE-89',
  };
  return cweMap[rule] || null;
}

function getOWASPCategory(ruleset: string): string | null {
  if (ruleset.includes('security')) return 'A03:2021-Injection';
  if (ruleset.includes('errorprone')) return 'A04:2021-Insecure Design';
  return null;
}
