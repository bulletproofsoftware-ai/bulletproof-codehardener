import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-syft');

interface SyftResult {
  artifacts: Array<{
    id: string;
    name: string;
    version: string;
    type: string;
    foundBy: string;
    locations: Array<{ path: string }>;
    language: string;
    licenses: Array<{ value: string; spdxExpression: string; type: string }>;
    cpes: Array<{ cpe: string }>;
    purl: string;
    metadataType: string;
    metadata: Record<string, unknown>;
  }>;
  source: {
    id: string;
    name: string;
    version: string;
    type: string;
    metadata: { path: string };
  };
  distro: { name: string; version: string; idLike: string[] };
  descriptor: { name: string; version: string };
  schema: { version: string; url: string };
}

// License risk mapping
// Order matters: check LGPL before GPL to avoid substring false matches
const HIGH_RISK_LICENSES = ['AGPL-3.0', 'SSPL-1.0'];
const MEDIUM_RISK_LICENSES = ['MPL-2.0', 'EPL-2.0'];
const RESTRICTED_LICENSES = ['GPL-2.0', 'GPL-3.0']; // copyleft (not weak copyleft)
const WEAK_COPYLEFT_LICENSES = ['LGPL-2.1', 'LGPL-3.0']; // dynamically linked = OK

function classifyLicense(license: string): 'high' | 'medium' | 'low' | null {
  // LGPL check must come before GPL to avoid substring match (LGPL contains GPL)
  if (WEAK_COPYLEFT_LICENSES.some(rl => license.includes(rl))) return 'low';
  if (HIGH_RISK_LICENSES.some(rl => license.includes(rl))) return 'high';
  if (RESTRICTED_LICENSES.some(rl => license.includes(rl))) return 'medium';
  if (MEDIUM_RISK_LICENSES.some(rl => license.includes(rl))) return 'medium';
  return null;
}

export async function runSyft(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Run Syft for SBOM generation (JSON for analysis + CycloneDX for standards compliance)
    const { stdout } = await execAsync(
      `syft dir:/scan-target -o json --quiet 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    // Also generate CycloneDX SBOM for attestation and standards compliance
    await execAsync(
      `syft dir:/scan-target -o cyclonedx-json --quiet > /tmp/sbom-cyclonedx.json 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    ).catch(() => {});

    if (stdout.trim()) {
      const result: SyftResult = JSON.parse(stdout);

      // Analyze dependencies for license compliance issues
      for (const artifact of result.artifacts || []) {
        const licenses = artifact.licenses || [];
        const licenseNames = licenses.map(l => l.spdxExpression || l.value).filter(Boolean);

        // Check for problematic licenses
        for (const license of licenseNames) {
          const risk = classifyLicense(license);
          if (risk === 'high') {
            findings.push({
              ruleId: 'SBOM-LICENSE-HIGH',
              severity: 'high',
              title: `High-Risk License: ${license} in ${artifact.name}`,
              description: `Package ${artifact.name}@${artifact.version} uses ${license} license which may have copyleft requirements incompatible with proprietary software.`,
              filePath: artifact.locations?.[0]?.path?.replace('/scan-target/', '') || null,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: `Package: ${artifact.name}\nVersion: ${artifact.version}\nLicense: ${license}\nPURL: ${artifact.purl}`,
              cweId: null,
              owaspCategory: 'A08:2021-Software and Data Integrity Failures',
              fixAvailable: true,
              fixDescription: `Review license compliance. Consider replacing ${artifact.name} with an alternative that uses a permissive license (MIT, Apache-2.0, BSD).`,
              metadata: {
                packageType: artifact.type,
                language: artifact.language,
                allLicenses: licenseNames,
                purl: artifact.purl,
                cpes: artifact.cpes,
              },
            });
          } else if (risk === 'medium') {
            findings.push({
              ruleId: 'SBOM-LICENSE-MEDIUM',
              severity: 'medium',
              title: `Copyleft License: ${license} in ${artifact.name}`,
              description: `Package ${artifact.name}@${artifact.version} uses ${license} which has copyleft provisions. Ensure compliance with license terms.`,
              filePath: artifact.locations?.[0]?.path?.replace('/scan-target/', '') || null,
              lineNumber: null,
              columnNumber: null,
              codeSnippet: `Package: ${artifact.name}\nVersion: ${artifact.version}\nLicense: ${license}`,
              cweId: null,
              owaspCategory: 'A08:2021-Software and Data Integrity Failures',
              fixAvailable: false,
              fixDescription: `Review ${license} license requirements to ensure your use case is compliant.`,
              metadata: {
                packageType: artifact.type,
                language: artifact.language,
                allLicenses: licenseNames,
                purl: artifact.purl,
              },
            });
          }
        }

        // Flag packages with no license information
        if (licenseNames.length === 0) {
          findings.push({
            ruleId: 'SBOM-LICENSE-UNKNOWN',
            severity: 'low',
            title: `Unknown License: ${artifact.name}@${artifact.version}`,
            description: `Package ${artifact.name} has no license information. This may indicate a compliance risk.`,
            filePath: artifact.locations?.[0]?.path?.replace('/scan-target/', '') || null,
            lineNumber: null,
            columnNumber: null,
            codeSnippet: `Package: ${artifact.name}\nVersion: ${artifact.version}\nType: ${artifact.type}`,
            cweId: null,
            owaspCategory: 'A08:2021-Software and Data Integrity Failures',
            fixAvailable: false,
            fixDescription: 'Verify the license for this package before using in production.',
            metadata: {
              packageType: artifact.type,
              language: artifact.language,
              purl: artifact.purl,
            },
          });
        }
      }

      // Store SBOM metadata for attestation
      logger.info(
        {
          totalPackages: result.artifacts?.length || 0,
          source: result.source?.name,
        },
        'SBOM generated'
      );
    }

    const parsedResult = stdout.trim() ? JSON.parse(stdout) as SyftResult : null;
    const totalPackages = parsedResult?.artifacts?.length || 0;
    const uniqueLanguages = new Set(
      parsedResult?.artifacts?.map(a => a.language).filter(Boolean) || []
    );

    // Build summarized SBOM package list for report rendering
    const sbomPackages = (parsedResult?.artifacts || []).map(a => ({
      name: a.name,
      version: a.version,
      type: a.type,
      language: a.language || '',
      license: (a.licenses || []).map(l => l.spdxExpression || l.value).filter(Boolean).join(', ') || 'Unknown',
    }));

    logger.info({ findingsCount: findings.length, totalPackages }, 'Syft scan completed');

    return {
      scanner: 'syft',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'SBOM generation (Syft JSON + CycloneDX)', 'License compliance analysis',
          'Copyleft license detection (AGPL, GPL, MPL)', 'Weak copyleft classification (LGPL)',
          'Unknown license flagging', 'Package URL (PURL) generation', 'CPE generation',
        ],
        scanScope: `SBOM of ${totalPackages} packages across ${uniqueLanguages.size} language(s): ${[...uniqueLanguages].join(', ') || 'N/A'}`,
        filesAnalyzed: totalPackages,
        rulesEvaluated: 4, // high-risk, restricted, medium-risk, unknown license checks
        configuration: 'Syft with JSON + CycloneDX output for SBOM standards compliance',
        sbomPackages,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Syft scan failed');
    return {
      scanner: 'syft',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
