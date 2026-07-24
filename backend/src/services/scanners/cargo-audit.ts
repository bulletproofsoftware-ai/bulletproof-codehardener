import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-cargo-audit');

const SCAN_TARGET = '/scan-target';

interface CargoAuditResult {
  vulnerabilities: {
    found: boolean;
    count: number;
    list: Array<{
      advisory: {
        id: string;
        title: string;
        description: string;
        date: string;
        url: string;
        categories: string[];
        cvss: string | null;
        severity: string | null;
        aliases: string[];
      };
      versions: {
        patched: string[];
        unaffected: string[];
      };
      package: {
        name: string;
        version: string;
        source: string;
      };
    }>;
  };
}

function mapSeverity(advisorySeverity: string | null): Severity {
  if (!advisorySeverity) return 'medium';
  const map: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'info',
    none: 'info',
  };
  return map[advisorySeverity.toLowerCase()] || 'medium';
}

export async function runCargoAudit(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    if (!existsSync(`${SCAN_TARGET}/Cargo.lock`)) {
      return {
        scanner: 'cargo-audit',
        success: true,
        skipped: true,
        skipReason: 'no_rust_project',
        skipHint: 'No Cargo.lock found — cargo-audit requires a Rust project with dependencies',
        findings: [],
        duration: Date.now() - startTime,
        rawOutput: 'Not a Rust project (no Cargo.lock found)',
      };
    }

    const { stdout } = await execAsync(
      `cd ${SCAN_TARGET} && cargo-audit audit --json 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (stdout.trim()) {
      const result: CargoAuditResult = JSON.parse(stdout);

      for (const vuln of result.vulnerabilities?.list || []) {
        const advisory = vuln.advisory;
        const pkg = vuln.package;
        const versions = vuln.versions;

        // Extract CVE IDs from aliases
        const cveIds = (advisory.aliases || []).filter(a => a.startsWith('CVE-'));
        const cveRef = cveIds.length > 0 ? ` (${cveIds.join(', ')})` : '';

        // Build fix description from patched versions
        const fixAvailable = versions.patched.length > 0;
        const fixDescription = fixAvailable
          ? `Update ${pkg.name} to version ${versions.patched.join(' or ')}`
          : null;

        findings.push({
          ruleId: advisory.id,
          severity: mapSeverity(advisory.severity),
          title: `${advisory.id}${cveRef}: ${advisory.title}`,
          description: advisory.description || `Security advisory for ${pkg.name}@${pkg.version}`,
          filePath: 'Cargo.lock',
          lineNumber: null,
          columnNumber: null,
          codeSnippet: `Package: ${pkg.name}\nVersion: ${pkg.version}\nAdvisory: ${advisory.id}\nPatched: ${versions.patched.join(', ') || 'No patch available'}`,
          cweId: null,
          owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
          fixAvailable,
          fixDescription,
          metadata: {
            advisoryUrl: advisory.url,
            advisoryDate: advisory.date,
            cvss: advisory.cvss,
            categories: advisory.categories,
            cveIds,
            patchedVersions: versions.patched,
            unaffectedVersions: versions.unaffected,
            packageSource: pkg.source,
          },
        });
      }
    }

    const uniquePackages = new Set(findings.map(f => f.codeSnippet?.split('\n')[0]?.replace('Package: ', '') || ''));
    const uniqueAdvisories = new Set(findings.map(f => f.ruleId));

    logger.info({ findingsCount: findings.length }, 'cargo-audit scan completed');

    return {
      scanner: 'cargo-audit',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: stdout,
      evidence: {
        checksPerformed: [
          'RustSec advisory database lookup',
          'Cargo.lock dependency resolution',
          'CVE cross-referencing',
          'Patched version detection',
          'CVSS severity scoring',
        ],
        scanScope: `Rust dependency audit: ${uniqueAdvisories.size} advisories across ${uniquePackages.size} vulnerable crates`,
        filesAnalyzed: 1,
        rulesEvaluated: uniqueAdvisories.size || undefined,
        configuration: 'cargo-audit with RustSec Advisory Database',
      },
    };
  } catch (error) {
    logger.error({ error }, 'cargo-audit scan failed');
    return {
      scanner: 'cargo-audit',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
