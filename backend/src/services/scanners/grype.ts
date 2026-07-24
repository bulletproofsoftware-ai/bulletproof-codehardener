import { exec } from 'child_process';
import { promisify } from 'util';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

const execAsync = promisify(exec);
const logger = createLogger('scanner-grype');

interface GrypeResult {
  matches: Array<{
    vulnerability: {
      id: string;
      dataSource: string;
      namespace: string;
      severity: string;
      urls: string[];
      description: string;
      cvss: Array<{
        version: string;
        vector: string;
        metrics: { baseScore: number };
        source: string;
      }>;
      fix: { versions: string[]; state: string };
      advisories: Array<{ id: string; link: string }>;
    };
    relatedVulnerabilities: Array<{ id: string; severity: string }>;
    matchDetails: Array<{ type: string; matcher: string; searchedBy: object }>;
    artifact: {
      id: string;
      name: string;
      version: string;
      type: string;
      foundBy: string;
      locations: Array<{ path: string }>;
      language: string;
      licenses: string[];
      cpes: string[];
      purl: string;
    };
  }>;
  source: { type: string; target: string };
  distro: { name: string; version: string };
}

function mapSeverity(grypeSeverity: string): Severity {
  const map: Record<string, Severity> = {
    Critical: 'critical',
    High: 'high',
    Medium: 'medium',
    Low: 'low',
    Negligible: 'info',
  };
  return map[grypeSeverity] || 'info';
}

function parseGrypeResults(result: GrypeResult, source: 'filesystem' | 'image'): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];

  for (const match of result.matches || []) {
    const vuln = match.vulnerability;
    const artifact = match.artifact;
    const location = artifact.locations?.[0]?.path || 'unknown';

    // Get CVSS score if available
    const cvssScore = vuln.cvss?.[0]?.metrics?.baseScore;

    findings.push({
      ruleId: vuln.id,
      severity: mapSeverity(vuln.severity),
      title: `${vuln.id}: Vulnerability in ${artifact.name}@${artifact.version}`,
      description: vuln.description || `Vulnerable package ${artifact.name} version ${artifact.version}`,
      filePath: source === 'filesystem' ? location.replace('/scan-target/', '') : location,
      lineNumber: null,
      columnNumber: null,
      codeSnippet: `Package: ${artifact.name}\nVersion: ${artifact.version}\nType: ${artifact.type}\nLanguage: ${artifact.language || 'N/A'}`,
      cweId: null,
      owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
      fixAvailable: vuln.fix?.versions?.length > 0,
      fixDescription: vuln.fix?.versions?.length
        ? `Update ${artifact.name} to version ${vuln.fix.versions.join(' or ')}`
        : null,
      metadata: {
        dataSource: vuln.dataSource,
        cvssScore,
        cvssVector: vuln.cvss?.[0]?.vector,
        purl: artifact.purl,
        advisories: vuln.advisories,
        urls: vuln.urls,
        scanSource: source,
      },
    });
  }

  return findings;
}

export async function runGrype(jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];
  const rawOutputParts: string[] = [];

  try {
    // 1. Always run filesystem scan
    const { stdout: fsStdout } = await execAsync(
      `grype dir:/scan-target -o json --quiet --by-cve --add-cpes-if-none 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    rawOutputParts.push(fsStdout);

    if (fsStdout.trim()) {
      const fsResult: GrypeResult = JSON.parse(fsStdout);
      findings.push(...parseGrypeResults(fsResult, 'filesystem'));
    }

    // 2. If containerImage is set, ALSO run image scan and merge findings
    if (jobData.containerImage) {
      logger.info({ image: jobData.containerImage }, 'Running additional Grype image scan');
      try {
        const { stdout: imgStdout } = await execAsync(
          `grype ${jobData.containerImage} -o json --quiet --by-cve --add-cpes-if-none 2>/dev/null || true`,
          { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }
        );

        rawOutputParts.push(imgStdout);

        if (imgStdout.trim()) {
          const imgResult: GrypeResult = JSON.parse(imgStdout);
          const imageFindings = parseGrypeResults(imgResult, 'image');
          findings.push(...imageFindings);
          logger.info({ imageFindingsCount: imageFindings.length, image: jobData.containerImage }, 'Grype image scan completed');
        }
      } catch (imgError) {
        logger.warn({ error: imgError, image: jobData.containerImage }, 'Grype image scan failed (filesystem scan results preserved)');
      }
    }

    // Extract audit evidence
    const allMatches = findings;
    const uniquePackages = new Set(allMatches.map(f => `${f.metadata?.purl || f.ruleId}`));
    const uniqueCVEs = new Set(allMatches.map(f => f.ruleId));

    logger.info({ findingsCount: findings.length }, 'Grype scan completed');

    return {
      scanner: 'grype',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: rawOutputParts.join('\n---\n'),
      evidence: {
        checksPerformed: [
          'CVE vulnerability matching', 'Dependency version analysis', 'CPE-based matching',
          'Advisory cross-referencing', 'Fix availability detection',
          ...(jobData.containerImage ? [`Container image scan: ${jobData.containerImage}`] : []),
        ],
        scanScope: `SCA analysis: ${uniqueCVEs.size} unique CVEs across ${uniquePackages.size} vulnerable packages${jobData.containerImage ? ` (filesystem + image ${jobData.containerImage})` : ' (filesystem)'}`,
        filesAnalyzed: uniquePackages.size || undefined,
        rulesEvaluated: uniqueCVEs.size || undefined,
        configuration: `Grype with --by-cve deduplication and --add-cpes-if-none${jobData.containerImage ? ` + image scan of ${jobData.containerImage}` : ''}`,
      },
    };
  } catch (error) {
    logger.error({ error }, 'Grype scan failed');
    return {
      scanner: 'grype',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
