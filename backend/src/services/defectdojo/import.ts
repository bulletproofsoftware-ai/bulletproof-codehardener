import { createLogger } from '../../utils/logger.js';
import { getDefectDojoClient } from './client.js';
import { ensureDefectDojoProduct } from './product-sync.js';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import type { ScannerResult } from '../../types/index.js';

const logger = createLogger('defectdojo-import');

/**
 * Maps Code Hardener scanner names to DefectDojo scan_type values.
 * Native importers have dedicated parsers in DefectDojo.
 * Everything else uses "Generic Findings Import" format.
 */
const SCAN_TYPE_MAP: Record<string, string> = {
  // Native importers (DD has built-in parsers)
  trivy: 'Trivy Scan',
  bandit: 'Bandit Scan',
  gitleaks: 'Gitleaks Scan',
  zap: 'ZAP Scan',
  nuclei: 'Nuclei Scan',
  grype: 'Anchore Grype',
  checkov: 'Checkov Scan',
  'eslint-security': 'ESLint Scan',

  // Generic import (DD doesn't have native parser)
  opengrep: 'Generic Findings Import',
  semgrep: 'Semgrep JSON Report',
  gosec: 'Gosec Scanner',
  pmd: 'Generic Findings Import',
  // detect-secrets removed: redundant with Gitleaks
  opa: 'Generic Findings Import',
  conftest: 'Generic Findings Import',
  syft: 'SBOM',
  cosign: 'Generic Findings Import',
  'in-toto': 'Generic Findings Import',
  newman: 'Generic Findings Import',
  pact: 'Generic Findings Import',
  restler: 'Generic Findings Import',
  playwright: 'Generic Findings Import',
  backstop: 'Generic Findings Import',
  pa11y: 'Generic Findings Import',
  locust: 'Generic Findings Import',
  artillery: 'Generic Findings Import',
  k6: 'Generic Findings Import',
  allure: 'Generic Findings Import',
};

/**
 * Convert scanner results to Generic Findings Import format for scanners
 * without native DD parsers.
 */
function toGenericFormat(result: ScannerResult): string {
  const findings = result.findings.map(f => ({
    title: f.title,
    description: f.description,
    severity: capitalizeFirst(f.severity),
    file_path: f.filePath || '',
    line: f.lineNumber || 0,
    cwe: f.cweId ? parseInt(f.cweId.replace('CWE-', '')) : undefined,
    vuln_id_from_tool: f.ruleId,
    mitigation: f.fixDescription || '',
    active: true,
    verified: false,
    static_finding: true,
    dynamic_finding: false,
  }));

  return JSON.stringify({ findings });
}

function capitalizeFirst(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * Import scan results to DefectDojo.
 * Creates an engagement for the scan, then imports each scanner's results.
 */
export async function importScanToDefectDojo(
  scanId: string,
  projectId: string,
  results: ScannerResult[],
  opts: { branch?: string; commitSha?: string; profile?: string } = {}
): Promise<{ engagementId: number; imported: number; failed: number } | null> {
  const client = getDefectDojoClient();
  if (!client.isEnabled()) return null;

  // Ensure product exists
  const productId = await ensureDefectDojoProduct(projectId);
  if (!productId) {
    logger.warn({ projectId }, 'No DefectDojo product for project');
    return null;
  }

  // Create engagement for this scan
  const engagement = await client.createEngagement(productId, `Scan ${scanId}`, {
    branch: opts.branch,
    commitSha: opts.commitSha,
    scanProfile: opts.profile,
  });

  if (!engagement) {
    logger.error({ scanId, productId }, 'Failed to create DefectDojo engagement');
    return null;
  }

  // Store engagement ID on scan
  await db.execute(sql`
    UPDATE scans SET defectdojo_engagement_id = ${engagement.id} WHERE id = ${scanId}
  `);

  let imported = 0;
  let failed = 0;

  // Import each scanner result
  for (const result of results) {
    if (!result.success || result.findings.length === 0) continue;

    const scanType = SCAN_TYPE_MAP[result.scanner];
    if (!scanType) {
      logger.warn({ scanner: result.scanner }, 'No DD scan type mapping, skipping');
      failed++;
      continue;
    }

    // Use rawOutput for native importers, convert for generic
    const isNative = scanType !== 'Generic Findings Import';
    const importData = isNative && result.rawOutput
      ? result.rawOutput
      : toGenericFormat(result);

    const importResult = await client.importScan(engagement.id, scanType, importData);

    if (importResult) {
      imported++;
      logger.debug(
        { scanner: result.scanner, findingsAffected: importResult.findings_affected },
        'Scanner results imported to DefectDojo'
      );
    } else {
      failed++;
      logger.warn({ scanner: result.scanner }, 'Failed to import to DefectDojo');
    }
  }

  // Close engagement
  await client.closeEngagement(engagement.id);

  logger.info(
    { scanId, engagementId: engagement.id, imported, failed },
    'Scan imported to DefectDojo'
  );

  return { engagementId: engagement.id, imported, failed };
}
