import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-license-finder');

const SCAN_TARGET = '/scan-target';

const COPYLEFT_LICENSES = new Set([
  'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0',
  'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only', 'LGPL-2.1-only', 'LGPL-3.0-only',
  'GPL-2.0-or-later', 'GPL-3.0-or-later', 'AGPL-3.0-or-later',
  'SSPL-1.0', 'EUPL-1.2', 'CPAL-1.0', 'MPL-2.0',
]);

const RESTRICTIVE_LICENSES = new Set([
  'LGPL-2.1', 'LGPL-3.0', 'LGPL-2.1-only', 'LGPL-3.0-only', 'MPL-2.0', 'EPL-2.0',
]);

function licenseSeverity(license: string): Severity {
  const upper = license.toUpperCase();
  if (upper.includes('AGPL') || upper.includes('SSPL')) return 'critical';
  if (upper.includes('GPL') && !upper.includes('LGPL')) return 'high';
  if (RESTRICTIVE_LICENSES.has(license)) return 'medium';
  if (license === 'unknown' || license === 'other') return 'medium';
  return 'info';
}

function isConcerning(license: string): boolean {
  if (COPYLEFT_LICENSES.has(license)) return true;
  if (RESTRICTIVE_LICENSES.has(license)) return true;
  const upper = license.toUpperCase();
  if (upper.includes('GPL') || upper.includes('SSPL') || upper.includes('AGPL')) return true;
  if (license === 'unknown' || license === 'other') return true;
  return false;
}

export async function runLicenseFinder(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    const hasManifest = ['package.json', 'Gemfile', 'requirements.txt', 'go.mod', 'pom.xml', 'build.gradle', 'composer.json', 'Cargo.toml']
      .some(f => existsSync(`${SCAN_TARGET}/${f}`));

    if (!hasManifest) {
      return { scanner: 'license-finder', success: true, skipped: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No package manifests found', skipReason: 'no_matching_files', skipHint: 'No package manifest found (package.json, Gemfile, requirements.txt, etc.)' };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && license_finder report --format csv --columns name version licenses 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
    );

    if (!stdout.trim()) {
      return { scanner: 'license-finder', success: true, findings: [], duration: Date.now() - startTime, rawOutput: 'No output from license_finder' };
    }

    const lines = stdout.trim().split('\n');
    let totalPackages = 0;
    let concerningCount = 0;

    for (const line of lines.slice(0, 500)) {
      const match = line.match(/^"?([^",]+)"?\s*,\s*"?([^",]*)"?\s*,\s*"?([^"]*)"?$/);
      if (!match) continue;
      const [, name, version, licenseStr] = match;
      const licenses = licenseStr.split(/,\s*/);
      totalPackages++;

      for (const license of licenses) {
        const trimmed = license.trim();
        if (!isConcerning(trimmed)) continue;
        concerningCount++;

        findings.push({
          ruleId: `LICENSE-${trimmed === 'unknown' ? 'UNKNOWN' : 'COPYLEFT'}`,
          severity: licenseSeverity(trimmed),
          title: `${trimmed === 'unknown' ? 'Unknown' : 'Copyleft'} license: ${name}@${version} (${trimmed})`,
          description: `Package "${name}" version ${version} uses the ${trimmed} license. ` +
            (trimmed === 'unknown' ? 'Unknown licenses pose legal risk — verify before distribution.' :
            'Copyleft licenses may require you to release your source code under the same license.'),
          filePath: null, lineNumber: null, columnNumber: null, codeSnippet: null,
          cweId: null, owaspCategory: null, fixAvailable: true,
          fixDescription: trimmed === 'unknown' ? `Verify the license of "${name}" and ensure compliance.` :
            `Replace "${name}" with a permissively-licensed alternative (MIT, Apache-2.0, BSD).`,
          metadata: { package: name, version, license: trimmed, allLicenses: licenses },
        });
      }
    }

    logger.info({ totalPackages, concerningCount, findingsCount: findings.length }, 'LicenseFinder scan completed');
    return {
      scanner: 'license-finder', success: true, findings, duration: Date.now() - startTime,
      rawOutput: `${totalPackages} packages scanned, ${concerningCount} concerning licenses`,
      evidence: {
        checksPerformed: ['Dependency license identification', 'Copyleft license detection (GPL, AGPL, SSPL)', 'Unknown license flagging', 'License compliance assessment'],
        scanScope: `${totalPackages} packages analyzed for license compliance`,
        rulesEvaluated: totalPackages,
      },
    };
  } catch (error) {
    logger.error({ error }, 'LicenseFinder scan failed');
    return { scanner: 'license-finder', success: false, findings: [], duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
