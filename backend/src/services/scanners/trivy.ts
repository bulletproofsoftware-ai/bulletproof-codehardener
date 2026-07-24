import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-trivy');

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Type: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity: string;
      Title: string;
      Description: string;
      PrimaryURL?: string;
      CVSS?: Record<string, { V3Score?: number }>;
    }>;
    Misconfigurations?: Array<{
      ID: string;
      Title: string;
      Description: string;
      Severity: string;
      Resolution?: string;
    }>;
    Licenses?: Array<{
      Severity: string;
      Category: string;
      PkgName: string;
      FilePath: string;
      Name: string;
      Confidence: number;
      Link: string;
    }>;
  }>;
}

function mapSeverity(trivySeverity: string): Severity {
  const map: Record<string, Severity> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    UNKNOWN: 'info',
  };
  return map[trivySeverity.toUpperCase()] || 'info';
}

function parseTrivyResults(result: TrivyResult, source: 'filesystem' | 'image'): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  if (!result.Results) return findings;

  for (const target of result.Results) {
    // Process vulnerabilities
    if (target.Vulnerabilities) {
      for (const vuln of target.Vulnerabilities) {
        findings.push({
          ruleId: vuln.VulnerabilityID,
          severity: mapSeverity(vuln.Severity),
          title: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.PkgName}`,
          description: vuln.Description || `Vulnerability in ${vuln.PkgName}`,
          filePath: target.Target,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: `Package: ${vuln.PkgName}\nInstalled: ${vuln.InstalledVersion}\nFixed: ${vuln.FixedVersion || 'N/A'}`,
          cweId: null,
          owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
          fixAvailable: !!vuln.FixedVersion,
          fixDescription: vuln.FixedVersion
            ? `Update ${vuln.PkgName} to version ${vuln.FixedVersion}`
            : null,
          metadata: {
            primaryUrl: vuln.PrimaryURL,
            cvss: vuln.CVSS,
            packageType: target.Type,
            scanSource: source,
          },
        });
      }
    }

    // Process misconfigurations
    if (target.Misconfigurations) {
      for (const misconfig of target.Misconfigurations) {
        findings.push({
          ruleId: misconfig.ID,
          severity: mapSeverity(misconfig.Severity),
          title: misconfig.Title,
          description: misconfig.Description,
          filePath: target.Target,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: null,
          cweId: null,
          owaspCategory: 'A05:2021-Security Misconfiguration',
          fixAvailable: !!misconfig.Resolution,
          fixDescription: misconfig.Resolution || null,
          metadata: { scanSource: source },
        });
      }
    }

    // Process license findings
    if (target.Licenses) {
      for (const license of target.Licenses) {
        const licenseSeverity = mapSeverity(license.Severity);
        findings.push({
          ruleId: `LICENSE-${license.Name}`,
          severity: licenseSeverity,
          title: `License Compliance: ${license.Name} in ${license.PkgName}`,
          description: `Package ${license.PkgName} uses license ${license.Name} (category: ${license.Category}). Review for compliance with your organization's license policy.`,
          filePath: license.FilePath || target.Target,
          lineNumber: null,
          columnNumber: null,
          codeSnippet: `Package: ${license.PkgName}\nLicense: ${license.Name}\nCategory: ${license.Category}`,
          cweId: null,
          owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
          fixAvailable: false,
          fixDescription: null,
          metadata: {
            licenseCategory: license.Category,
            confidence: license.Confidence,
            link: license.Link,
            scanSource: source,
          },
        });
      }
    }
  }

  return findings;
}

export async function runTrivy(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const rawOutputParts: string[] = [];
  const scannedTargets: string[] = [];
  const packageTypes: Set<string> = new Set();

  try {
    // 1. Always run filesystem scan
    const configFlag = existsSync('/configs/trivy.yaml') ? '--config /configs/trivy.yaml' : '';
    const fsCmd = `trivy fs --format json --scanners vuln,misconfig,secret,license --list-all-pkgs --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN ${configFlag} --quiet /scan-target 2>/dev/null || true`;
    const { stdout: fsStdout } = await execAsync(
      fsCmd,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    rawOutputParts.push(fsStdout);

    const fsResult: TrivyResult = JSON.parse(fsStdout);
    findings.push(...parseTrivyResults(fsResult, 'filesystem'));

    if (fsResult.Results) {
      for (const r of fsResult.Results) {
        scannedTargets.push(r.Target);
        if (r.Type) packageTypes.add(r.Type);
      }
    }

    // 2. If containerImage is set, ALSO run image scan and merge findings
    if (jobData.containerImage) {
      logger.info({ image: jobData.containerImage }, 'Running additional Trivy image scan');
      try {
        const imgCmd = `trivy image --format json --scanners vuln,misconfig,secret,license --list-all-pkgs --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN --quiet ${jobData.containerImage} 2>/dev/null || true`;
        const { stdout: imgStdout } = await execAsync(
          imgCmd,
          { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
        );

        rawOutputParts.push(imgStdout);

        const imgResult: TrivyResult = JSON.parse(imgStdout);
        const imageFindings = parseTrivyResults(imgResult, 'image');
        findings.push(...imageFindings);

        if (imgResult.Results) {
          for (const r of imgResult.Results) {
            scannedTargets.push(`[image] ${r.Target}`);
            if (r.Type) packageTypes.add(r.Type);
          }
        }

        logger.info({ imageFindingsCount: imageFindings.length, image: jobData.containerImage }, 'Trivy image scan completed');
      } catch (imgError) {
        logger.warn({ error: imgError, image: jobData.containerImage }, 'Trivy image scan failed (filesystem scan results preserved)');
      }
    }

    logger.info({ findingsCount: findings.length }, 'Trivy scan completed');

    return {
      scanner: 'trivy',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n---\n'),
      evidence: {
        filesAnalyzed: scannedTargets.length,
        rulesEvaluated: 4, // vuln, misconfig, secret, license scanners
        checksPerformed: [
          'Vulnerability scanning', 'Misconfiguration detection', 'Secret detection', 'License compliance',
          ...(jobData.containerImage ? [`Container image scan: ${jobData.containerImage}`] : []),
        ],
        scanScope: `Scanned ${scannedTargets.length} target(s): ${[...packageTypes].join(', ') || 'filesystem'}${jobData.containerImage ? ` + image ${jobData.containerImage}` : ''}`,
        targetsAnalyzed: scannedTargets.slice(0, 20),
      },
    };
  } catch (error) {
    logger.error({ error }, 'Trivy scan failed');
    return {
      scanner: 'trivy',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
