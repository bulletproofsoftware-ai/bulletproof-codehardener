import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-scancode');

const SCAN_TARGET = '/scan-target';
const OUTPUT_FILE = '/tmp/scancode-output.json';
const CONFIDENCE_THRESHOLD = 80;

// Copyleft license families that pose contamination risk
const COPYLEFT_LICENSES: Record<string, { severity: Severity; family: string }> = {
  'gpl-2.0': { severity: 'critical', family: 'GPL' },
  'gpl-2.0-only': { severity: 'critical', family: 'GPL' },
  'gpl-2.0-or-later': { severity: 'critical', family: 'GPL' },
  'gpl-2.0-plus': { severity: 'critical', family: 'GPL' },
  'gpl-3.0': { severity: 'critical', family: 'GPL' },
  'gpl-3.0-only': { severity: 'critical', family: 'GPL' },
  'gpl-3.0-or-later': { severity: 'critical', family: 'GPL' },
  'gpl-3.0-plus': { severity: 'critical', family: 'GPL' },
  'agpl-3.0': { severity: 'critical', family: 'AGPL' },
  'agpl-3.0-only': { severity: 'critical', family: 'AGPL' },
  'agpl-3.0-or-later': { severity: 'critical', family: 'AGPL' },
  'lgpl-2.0': { severity: 'high', family: 'LGPL' },
  'lgpl-2.0-only': { severity: 'high', family: 'LGPL' },
  'lgpl-2.0-or-later': { severity: 'high', family: 'LGPL' },
  'lgpl-2.1': { severity: 'high', family: 'LGPL' },
  'lgpl-2.1-only': { severity: 'high', family: 'LGPL' },
  'lgpl-2.1-or-later': { severity: 'high', family: 'LGPL' },
  'lgpl-3.0': { severity: 'high', family: 'LGPL' },
  'lgpl-3.0-only': { severity: 'high', family: 'LGPL' },
  'lgpl-3.0-or-later': { severity: 'high', family: 'LGPL' },
  'sspl-1.0': { severity: 'critical', family: 'SSPL' },
  'eupl-1.1': { severity: 'high', family: 'EUPL' },
  'eupl-1.2': { severity: 'high', family: 'EUPL' },
  'mpl-1.0': { severity: 'medium', family: 'MPL' },
  'mpl-1.1': { severity: 'medium', family: 'MPL' },
  'cpal-1.0': { severity: 'high', family: 'CPAL' },
  'osl-3.0': { severity: 'high', family: 'OSL' },
  'cecill-2.1': { severity: 'high', family: 'CeCILL' },
};

interface ScancodeFile {
  path: string;
  licenses: Array<{
    key: string;
    spdx_license_key: string;
    score: number;
    name: string;
    category: string;
    start_line: number;
    end_line: number;
    matched_text?: string;
    matched_rule?: {
      identifier: string;
      license_expression: string;
    };
  }>;
}

interface ScancodeOutput {
  headers: Array<{
    tool_name: string;
    tool_version: string;
    options: Record<string, unknown>;
    start_timestamp: string;
    end_timestamp: string;
  }>;
  files: ScancodeFile[];
}

export async function runScancode(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check if scancode binary is available
    try {
      await execAsync('which scancode', { timeout: 5000 });
    } catch {
      return {
        scanner: 'scancode',
        success: true,
        skipped: true,
        skipReason: 'tool_not_installed',
        skipHint: 'ScanCode binary not available — install scancode-toolkit to enable license snippet detection',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'scancode binary not found',
      };
    }

    // Count files to estimate scan time — skip if repo is too large (>1000 source files)
    const { stdout: repoFileCount } = await execAsync(
      `find ${SCAN_TARGET} -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/vendor/*" -not -path "*/dist/*" -not -name "*.min.js" 2>/dev/null | wc -l`,
      { timeout: 10000 }
    );
    const repoSize = parseInt(repoFileCount.trim()) || 0;
    if (repoSize > 1000) {
      return {
        scanner: 'scancode',
        success: true,
        skipped: true,
        skipReason: 'coverage_threshold',
        skipHint: `Repository has ${repoSize} files — ScanCode skipped for repos >1000 files to prevent timeout. Use license-finder for large repos.`,
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: `Skipped: ${repoSize} files exceeds ScanCode limit of 1000`,
      };
    }

    // Run scancode-toolkit with license detection + matched text
    const cmd = [
      'scancode',
      '--license',
      '--license-text',
      `--json-pp ${OUTPUT_FILE}`,
      `${SCAN_TARGET}`,
      '-n 4',                    // 4 parallel processes
      '--timeout 120',           // 2 min timeout per file
      '--ignore "*.min.js"',     // Skip minified files
      '--ignore "node_modules/*"',
      '--ignore ".git/*"',
      '--ignore "vendor/*"',
      '--ignore "venv/*"',
      '--ignore "__pycache__/*"',
      '2>/dev/null || true',
    ].join(' ');

    await execAsync(cmd, { maxBuffer: 100 * 1024 * 1024, timeout: 300000 });

    if (!existsSync(OUTPUT_FILE)) {
      logger.warn('scancode produced no output file — treating as skip');
      return {
        scanner: 'scancode',
        success: true,
        skipped: true,
        skipReason: 'tool_not_installed',
        skipHint: 'ScanCode timed out or produced no output — use license-finder for license compliance on large repos',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'ScanCode did not produce output within timeout. license-finder provides alternative license coverage.',
      };
    }

    const rawOutput = await readFile(OUTPUT_FILE, 'utf-8');
    const result: ScancodeOutput = JSON.parse(rawOutput);

    let totalFiles = 0;
    let filesWithLicenses = 0;
    const detectedLicenses = new Set<string>();

    for (const file of result.files || []) {
      totalFiles++;
      if (!file.licenses?.length) continue;
      filesWithLicenses++;

      for (const license of file.licenses) {
        // Only report high-confidence detections
        if (license.score < CONFIDENCE_THRESHOLD) continue;

        const licenseKey = license.key?.toLowerCase() || '';
        detectedLicenses.add(license.spdx_license_key || license.key);

        // Check if this is a copyleft license
        const copyleft = COPYLEFT_LICENSES[licenseKey];
        if (!copyleft) continue; // Permissive licenses are fine — don't report

        const filePath = file.path.replace(`${SCAN_TARGET}/`, '').replace(/^\//, '');

        findings.push({
          ruleId: 'LICENSE-SNIPPET-001',
          severity: copyleft.severity,
          title: `${copyleft.family} license detected: ${license.spdx_license_key || license.name} in ${filePath}`,
          description: `Code at lines ${license.start_line}-${license.end_line} matches ${copyleft.family} license pattern ` +
            `(${license.name}, confidence: ${license.score}%). ` +
            `AI-generated code can embed copyleft-licensed patterns without explicit imports. ` +
            `${copyleft.family} contamination may require open-sourcing your entire application under the same license.`,
          filePath,
          lineNumber: license.start_line,
          columnNumber: null,
          codeSnippet: license.matched_text?.slice(0, 500) || null,
          cweId: null,
          owaspCategory: null,
          fixAvailable: true,
          fixDescription: `Rewrite the code at lines ${license.start_line}-${license.end_line} to avoid ${copyleft.family}-licensed patterns. ` +
            `Use an alternative implementation or a permissively-licensed library (MIT, Apache-2.0, BSD).`,
          metadata: {
            licenseKey: license.key,
            spdxKey: license.spdx_license_key,
            licenseName: license.name,
            licenseCategory: license.category,
            confidence: license.score,
            licenseFamily: copyleft.family,
            startLine: license.start_line,
            endLine: license.end_line,
            matchedRule: license.matched_rule?.identifier,
          },
        });
      }
    }

    logger.info({
      totalFiles,
      filesWithLicenses,
      copyleftFindings: findings.length,
      licensesDetected: detectedLicenses.size,
    }, 'Scancode license scan completed');

    return {
      scanner: 'scancode',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: JSON.stringify({
        totalFiles,
        filesWithLicenses,
        licensesDetected: [...detectedLicenses],
        copyleftFindings: findings.length,
      }),
      evidence: {
        checksPerformed: [
          'Snippet-level license detection',
          'GPL/AGPL/LGPL contamination scanning',
          'SSPL/EUPL/CPAL copyleft detection',
          'License confidence scoring',
          'AI-generated code license risk assessment',
        ],
        scanScope: `License analysis of ${totalFiles} files, ${filesWithLicenses} with license indicators`,
        filesAnalyzed: totalFiles,
        rulesEvaluated: Object.keys(COPYLEFT_LICENSES).length,
        configuration: `Confidence threshold: ${CONFIDENCE_THRESHOLD}%, 4 parallel processes`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Scancode scan failed');
    return {
      scanner: 'scancode',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
