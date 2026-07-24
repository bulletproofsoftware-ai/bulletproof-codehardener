import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { createLogger } from '../../utils/logger.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type { ScannerResult, NormalizedFinding, Severity } from '../../types/index.js';

// Intentional use of exec(): All command strings are constant literals with no user input.
const execAsync = promisify(exec);
const logger = createLogger('scanner-cdxgen');

const SCAN_TARGET = '/scan-target';

const PACKAGE_MANIFESTS = [
  'package.json',
  'requirements.txt',
  'go.mod',
  'Cargo.toml',
  'pom.xml',
  'build.gradle',
  'Gemfile',
  'composer.json',
];

interface CdxgenVulnerability {
  id: string;
  source?: { name: string; url: string };
  ratings?: Array<{ severity: string; score?: number; method?: string }>;
  cwes?: Array<number>;
  description?: string;
  recommendation?: string;
  advisories?: Array<{ title: string; url: string }>;
  affects?: Array<{ ref: string }>;
}

interface CdxgenComponent {
  type: string;
  name: string;
  version: string;
  purl?: string;
  'bom-ref'?: string;
  licenses?: Array<{ license?: { id?: string; name?: string } }>;
  scope?: string;
  group?: string;
}

interface CdxgenBom {
  bomFormat: string;
  specVersion: string;
  components?: CdxgenComponent[];
  vulnerabilities?: CdxgenVulnerability[];
  metadata?: {
    timestamp?: string;
    tools?: Array<{ name: string; version: string }>;
    component?: { name: string; type: string; version?: string };
  };
  dependencies?: Array<{ ref: string; dependsOn?: string[] }>;
}

function mapSeverity(cdxgenSeverity: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info',
    none: 'info',
    unknown: 'info',
  };
  return map[cdxgenSeverity?.toLowerCase()] || 'info';
}

export async function runCdxgen(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();
  const findings: NormalizedFinding[] = [];

  try {
    // Check for any package manifest
    const hasManifest = PACKAGE_MANIFESTS.some(m => existsSync(`${SCAN_TARGET}/${m}`));
    if (!hasManifest) {
      logger.info('No package manifests found, skipping cdxgen');
      return {
        scanner: 'cdxgen',
        success: true,
        skipped: true,
        findings: [],
        duration: Date.now() - startTime,
        skipReason: 'no_matching_files',
        skipHint: 'No package manifest found for SBOM generation',
        evidence: {
          checksPerformed: ['Package manifest detection'],
          scanScope: 'Skipped — no supported package manifests found',
          configuration: 'cdxgen CycloneDX SBOM generator',
        },
      };
    }

    // Run cdxgen to produce a CycloneDX SBOM
    await execAsync(
      `cd ${SCAN_TARGET} && cdxgen -o /tmp/cdxgen-sbom.json . 2>/dev/null || true`,
      { maxBuffer: 50 * 1024 * 1024 }
    );

    if (!existsSync('/tmp/cdxgen-sbom.json')) {
      logger.warn('cdxgen did not produce output file');
      return {
        scanner: 'cdxgen',
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: 'cdxgen did not produce an SBOM output file',
      };
    }

    const raw = await readFile('/tmp/cdxgen-sbom.json', 'utf-8');
    const bom: CdxgenBom = JSON.parse(raw);

    const components = bom.components || [];
    const vulnerabilities = bom.vulnerabilities || [];

    // Build a lookup from bom-ref to component for enriching vulnerability findings
    const refToComponent = new Map<string, CdxgenComponent>();
    for (const comp of components) {
      if (comp['bom-ref']) {
        refToComponent.set(comp['bom-ref'], comp);
      }
    }

    // Create findings from vulnerabilities discovered by cdxgen
    for (const vuln of vulnerabilities) {
      const severity = vuln.ratings?.[0]?.severity || 'unknown';
      const cvssScore = vuln.ratings?.[0]?.score;
      const cweIds = vuln.cwes || [];

      // Resolve affected component
      const affectedRef = vuln.affects?.[0]?.ref;
      const affectedComponent = affectedRef ? refToComponent.get(affectedRef) : undefined;
      const packageName = affectedComponent
        ? `${affectedComponent.group ? affectedComponent.group + '/' : ''}${affectedComponent.name}`
        : 'unknown';
      const packageVersion = affectedComponent?.version || 'unknown';

      findings.push({
        ruleId: vuln.id,
        severity: mapSeverity(severity),
        title: `${vuln.id}: Vulnerability in ${packageName}@${packageVersion}`,
        description: vuln.description || `Vulnerability ${vuln.id} found in ${packageName}@${packageVersion}`,
        filePath: null,
        lineNumber: null,
        columnNumber: null,
        codeSnippet: `Package: ${packageName}\nVersion: ${packageVersion}\nPURL: ${affectedComponent?.purl || 'N/A'}`,
        cweId: cweIds.length > 0 ? `CWE-${cweIds[0]}` : null,
        owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
        fixAvailable: !!vuln.recommendation,
        fixDescription: vuln.recommendation || null,
        metadata: {
          source: vuln.source,
          cvssScore,
          advisories: vuln.advisories,
          purl: affectedComponent?.purl,
          allCwes: cweIds.map(c => `CWE-${c}`),
        },
      });
    }

    // Gather SBOM stats
    const componentTypes = new Map<string, number>();
    for (const comp of components) {
      const t = comp.type || 'unknown';
      componentTypes.set(t, (componentTypes.get(t) || 0) + 1);
    }

    const sbomPackages = components.map(c => ({
      name: `${c.group ? c.group + '/' : ''}${c.name}`,
      version: c.version,
      type: c.type,
      language: c.type || 'unknown',
      license: c.licenses
        ?.map(l => l.license?.id || l.license?.name)
        .filter(Boolean)
        .join(', ') || 'Unknown',
    }));

    logger.info(
      { findingsCount: findings.length, componentCount: components.length, vulnerabilityCount: vulnerabilities.length },
      'cdxgen scan completed'
    );

    return {
      scanner: 'cdxgen',
      success: true,
      findings,
      duration: Date.now() - startTime,
      rawOutput: raw,
      evidence: {
        checksPerformed: [
          'CycloneDX SBOM generation (cdxgen)',
          'Dependency enumeration',
          'Vulnerability detection from advisory databases',
          'Component license extraction',
        ],
        scanScope: `SBOM: ${components.length} components, ${vulnerabilities.length} vulnerabilities detected`,
        filesAnalyzed: components.length,
        rulesEvaluated: vulnerabilities.length,
        configuration: 'cdxgen with CycloneDX JSON output',
        sbomPackages,
        targetsAnalyzed: Array.from(componentTypes.entries()).map(([t, c]) => `${t}: ${c}`),
      },
    };
  } catch (error) {
    logger.error({ error }, 'cdxgen scan failed');
    return {
      scanner: 'cdxgen',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
