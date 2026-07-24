/**
 * Compliance Evidence Generator
 *
 * Generates compliance evidence documents mapping Code Hardener scan results
 * to regulatory framework controls. Supports SOC 2 Type II and ISO 27001.
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('compliance-generator');

// ============================================================================
// SOC 2 Trust Services Criteria → Scanner Mapping
// ============================================================================

interface ControlMapping {
  controlId: string;
  controlTitle: string;
  description: string;
  scanners: string[];
  evidenceType: 'scan_result' | 'attestation' | 'policy' | 'configuration';
  findingSeverities?: string[];
}

const SOC2_MAPPINGS: ControlMapping[] = [
  // CC6: Logical and Physical Access Controls
  {
    controlId: 'CC6.1',
    controlTitle: 'Logical Access Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
    scanners: ['bandit', 'gosec', 'eslint-security', 'opengrep'],
    evidenceType: 'scan_result',
    findingSeverities: ['critical', 'high'],
  },
  {
    controlId: 'CC6.6',
    controlTitle: 'System Boundary Protection',
    description: 'The entity implements logical access security measures to protect against threats from outside its system boundaries.',
    scanners: ['nuclei', 'zap', 'checkov'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'CC6.7',
    controlTitle: 'Transmission Security',
    description: 'The entity restricts the transmission, movement, and removal of information to authorized users.',
    scanners: ['gitleaks'],
    evidenceType: 'scan_result',
  },

  // CC7: System Operations
  {
    controlId: 'CC7.1',
    controlTitle: 'Detection of Changes',
    description: 'To meet its objectives, the entity uses detection and monitoring procedures.',
    scanners: ['trivy', 'grype'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'CC7.2',
    controlTitle: 'Monitoring for Anomalies',
    description: 'The entity monitors system components for anomalies indicative of malicious acts or compromises.',
    scanners: ['nuclei'],
    evidenceType: 'scan_result',
  },

  // CC8: Change Management
  {
    controlId: 'CC8.1',
    controlTitle: 'Change Management Process',
    description: 'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.',
    scanners: ['opengrep', 'pmd', 'eslint-security'],
    evidenceType: 'scan_result',
  },

  // CC9: Risk Mitigation
  {
    controlId: 'CC9.1',
    controlTitle: 'Risk Identification and Assessment',
    description: 'The entity identifies, selects, and develops risk mitigation activities.',
    scanners: ['trivy', 'grype', 'syft'],
    evidenceType: 'scan_result',
  },

  // Availability
  {
    controlId: 'A1.1',
    controlTitle: 'Capacity Management',
    description: 'The entity maintains, monitors, and evaluates current processing capacity and use.',
    scanners: ['locust', 'artillery'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A1.2',
    controlTitle: 'Environmental Protections',
    description: 'The entity authorizes, designs, develops, and implements activities to protect against environmental threats.',
    scanners: ['checkov', 'dockle'],
    evidenceType: 'scan_result',
  },

  // Processing Integrity
  {
    controlId: 'PI1.1',
    controlTitle: 'Processing Integrity Controls',
    description: 'The entity implements policies and procedures over system processing.',
    scanners: ['newman', 'pact', 'playwright'],
    evidenceType: 'scan_result',
  },

  // Confidentiality
  {
    controlId: 'C1.1',
    controlTitle: 'Confidential Information Protection',
    description: 'The entity identifies and maintains confidential information.',
    scanners: ['gitleaks', 'bandit'],
    evidenceType: 'scan_result',
  },

  // Supply Chain Integrity
  {
    controlId: 'CC9.2',
    controlTitle: 'Supply Chain Risk Management',
    description: 'The entity assesses and manages risks associated with vendors and business partners.',
    scanners: ['syft', 'cosign', 'socket', 'trivy'],
    evidenceType: 'attestation',
  },
];

// ============================================================================
// ISO 27001:2022 Annex A → Scanner Mapping
// ============================================================================

const ISO27001_MAPPINGS: ControlMapping[] = [
  // A.5: Organizational controls
  {
    controlId: 'A.5.23',
    controlTitle: 'Information security for use of cloud services',
    description: 'Processes for acquisition, use, management, and exit from cloud services shall be established.',
    scanners: ['checkov', 'dockle'],
    evidenceType: 'scan_result',
  },

  // A.8: Technological controls
  {
    controlId: 'A.8.1',
    controlTitle: 'User endpoint devices',
    description: 'Information stored on, processed by or accessible via user endpoint devices shall be protected.',
    scanners: ['gitleaks'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.4',
    controlTitle: 'Access to source code',
    description: 'Read and write access to source code, development tools and software libraries shall be managed.',
    scanners: ['gitleaks', 'cosign', 'socket'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.8',
    controlTitle: 'Management of technical vulnerabilities',
    description: 'Information about technical vulnerabilities of information systems shall be obtained and appropriate measures taken.',
    scanners: ['trivy', 'grype', 'syft'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.9',
    controlTitle: 'Configuration management',
    description: 'Configurations, including security configurations, of hardware, software, services and networks shall be managed.',
    scanners: ['checkov', 'conftest', 'opa'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.12',
    controlTitle: 'Data leakage prevention',
    description: 'Data leakage prevention measures shall be applied.',
    scanners: ['gitleaks', 'bandit'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.16',
    controlTitle: 'Monitoring activities',
    description: 'Networks, systems and applications shall be monitored for anomalous behaviour.',
    scanners: ['nuclei', 'zap'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.25',
    controlTitle: 'Secure development life cycle',
    description: 'Rules for the secure development of software shall be established and applied.',
    scanners: ['opengrep', 'bandit', 'gosec', 'eslint-security', 'pmd'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.26',
    controlTitle: 'Application security requirements',
    description: 'Information security requirements shall be identified, specified and approved.',
    scanners: ['newman', 'pact', 'restler', 'playwright'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.27',
    controlTitle: 'Secure system architecture and engineering',
    description: 'Principles for engineering secure systems shall be established.',
    scanners: ['checkov', 'dockle', 'conftest'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.28',
    controlTitle: 'Secure coding',
    description: 'Secure coding principles shall be applied to software development.',
    scanners: ['opengrep', 'bandit', 'gosec', 'eslint-security', 'pmd'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.29',
    controlTitle: 'Security testing in development and acceptance',
    description: 'Security testing processes shall be defined and implemented.',
    scanners: ['nuclei', 'zap', 'newman', 'playwright'],
    evidenceType: 'scan_result',
  },
  {
    controlId: 'A.8.31',
    controlTitle: 'Separation of development, test and production',
    description: 'Development, testing and production environments shall be separated.',
    scanners: ['checkov', 'conftest'],
    evidenceType: 'configuration',
  },
];

// ============================================================================
// Evidence Collection
// ============================================================================

export interface ComplianceEvidence {
  controlId: string;
  controlTitle: string;
  framework: 'soc2' | 'iso27001';
  status: 'pass' | 'partial' | 'fail' | 'not_tested';
  evidence: {
    scanner: string;
    scanDate: string;
    findingsCount: number;
    criticalCount: number;
    highCount: number;
    attestationId?: string;
  }[];
  notes: string;
}

export interface ComplianceReport {
  framework: 'soc2' | 'iso27001';
  generatedAt: string;
  projectId: string;
  projectName: string;
  overallStatus: 'compliant' | 'partial' | 'non_compliant';
  controlsCovered: number;
  controlsTotal: number;
  controlsPassing: number;
  evidence: ComplianceEvidence[];
}

/**
 * Generate a compliance report for a project
 */
export async function generateComplianceReport(
  projectId: string,
  framework: 'soc2' | 'iso27001'
): Promise<ComplianceReport> {
  const mappings = framework === 'soc2' ? SOC2_MAPPINGS : ISO27001_MAPPINGS;

  // Get project info
  const projectResult = await db.execute(
    sql`SELECT id, name FROM projects WHERE id = ${projectId}`
  );
  if (projectResult.rows.length === 0) {
    throw new Error(`Project ${projectId} not found`);
  }
  const project = projectResult.rows[0] as any;

  // Get the most recent completed scan
  const scanResult = await db.execute(
    sql`SELECT id, completed_at, profile FROM scans
        WHERE project_id = ${projectId} AND status = 'completed'
        ORDER BY completed_at DESC LIMIT 1`
  );

  // Get all findings for this project from recent scans
  const findingsResult = await db.execute(
    sql`SELECT f.scanner, f.severity, COUNT(*) as count
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        WHERE f.project_id = ${projectId}
        AND s.status = 'completed'
        AND s.completed_at > NOW() - INTERVAL '30 days'
        GROUP BY f.scanner, f.severity`
  );

  // Build scanner findings index
  const scannerFindings: Record<string, { total: number; critical: number; high: number }> = {};
  for (const row of findingsResult.rows as any[]) {
    if (!scannerFindings[row.scanner]) {
      scannerFindings[row.scanner] = { total: 0, critical: 0, high: 0 };
    }
    const count = parseInt(row.count, 10);
    scannerFindings[row.scanner].total += count;
    if (row.severity === 'critical') scannerFindings[row.scanner].critical += count;
    if (row.severity === 'high') scannerFindings[row.scanner].high += count;
  }

  // Get attestations
  const attestResult = await db.execute(
    sql`SELECT a.id, a.scan_id, a.signed_at
        FROM attestations a
        JOIN scans s ON s.id = a.scan_id
        WHERE s.project_id = ${projectId}
        AND a.signed_at > NOW() - INTERVAL '30 days'
        ORDER BY a.signed_at DESC`
  );
  const attestations = attestResult.rows as any[];

  // Collect evidence for each control
  const evidence: ComplianceEvidence[] = [];
  let controlsPassing = 0;

  const scanDate = scanResult.rows.length > 0
    ? (scanResult.rows[0] as any).completed_at?.toISOString() || new Date().toISOString()
    : new Date().toISOString();

  for (const mapping of mappings) {
    const controlEvidence: ComplianceEvidence['evidence'] = [];
    let hasScanner = false;

    for (const scanner of mapping.scanners) {
      const findings = scannerFindings[scanner];
      if (findings) {
        hasScanner = true;
        controlEvidence.push({
          scanner,
          scanDate,
          findingsCount: findings.total,
          criticalCount: findings.critical,
          highCount: findings.high,
        });
      } else {
        // Scanner ran with no findings = good
        controlEvidence.push({
          scanner,
          scanDate,
          findingsCount: 0,
          criticalCount: 0,
          highCount: 0,
        });
      }
    }

    // Add attestation evidence if applicable
    if (mapping.evidenceType === 'attestation' && attestations.length > 0) {
      controlEvidence.push({
        scanner: 'sigstore-attestation',
        scanDate: attestations[0].signed_at?.toISOString() || scanDate,
        findingsCount: 0,
        criticalCount: 0,
        highCount: 0,
        attestationId: attestations[0].id,
      });
    }

    // Determine control status
    let status: ComplianceEvidence['status'];
    const totalCritical = controlEvidence.reduce((sum, e) => sum + e.criticalCount, 0);
    const totalHigh = controlEvidence.reduce((sum, e) => sum + e.highCount, 0);

    if (!hasScanner && scanResult.rows.length === 0) {
      status = 'not_tested';
    } else if (totalCritical > 0) {
      status = 'fail';
    } else if (totalHigh > 0) {
      status = 'partial';
    } else {
      status = 'pass';
      controlsPassing++;
    }

    let notes = '';
    if (status === 'fail') {
      notes = `${totalCritical} critical findings must be remediated.`;
    } else if (status === 'partial') {
      notes = `${totalHigh} high-severity findings should be addressed.`;
    } else if (status === 'pass') {
      notes = 'No critical or high-severity findings detected.';
    } else {
      notes = 'No recent scan data available for this control.';
    }

    evidence.push({
      controlId: mapping.controlId,
      controlTitle: mapping.controlTitle,
      framework,
      status,
      evidence: controlEvidence,
      notes,
    });
  }

  const controlsTotal = mappings.length;
  const controlsCovered = evidence.filter(e => e.status !== 'not_tested').length;

  let overallStatus: ComplianceReport['overallStatus'];
  if (controlsPassing === controlsTotal) {
    overallStatus = 'compliant';
  } else if (evidence.some(e => e.status === 'fail')) {
    overallStatus = 'non_compliant';
  } else {
    overallStatus = 'partial';
  }

  const report: ComplianceReport = {
    framework,
    generatedAt: new Date().toISOString(),
    projectId,
    projectName: project.name,
    overallStatus,
    controlsCovered,
    controlsTotal,
    controlsPassing,
    evidence,
  };

  logger.info({
    projectId,
    framework,
    overallStatus,
    controlsCovered,
    controlsTotal,
    controlsPassing,
  }, 'Compliance report generated');

  return report;
}

/**
 * Generate a compliance diff between two time periods
 */
export async function generateComplianceDiff(
  projectId: string,
  framework: 'soc2' | 'iso27001',
  previousReportDate: string
): Promise<{
  newPassing: string[];
  newFailing: string[];
  unchanged: string[];
}> {
  // Current state
  const current = await generateComplianceReport(projectId, framework);

  // Compare with previous findings from before the date
  const previousFindings = await db.execute(
    sql`SELECT f.scanner, f.severity, COUNT(*) as count
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        WHERE f.project_id = ${projectId}
        AND s.completed_at < ${previousReportDate}::timestamptz
        AND s.completed_at > ${previousReportDate}::timestamptz - INTERVAL '30 days'
        GROUP BY f.scanner, f.severity`
  );

  const prevScannerFindings: Record<string, boolean> = {};
  for (const row of previousFindings.rows as any[]) {
    if (row.severity === 'critical' || row.severity === 'high') {
      prevScannerFindings[row.scanner] = true;
    }
  }

  const newPassing: string[] = [];
  const newFailing: string[] = [];
  const unchanged: string[] = [];

  const mappings = framework === 'soc2' ? SOC2_MAPPINGS : ISO27001_MAPPINGS;

  for (const control of current.evidence) {
    const mapping = mappings.find(m => m.controlId === control.controlId);
    if (!mapping) continue;

    const prevHadIssues = mapping.scanners.some(s => prevScannerFindings[s]);
    const currentPassing = control.status === 'pass';

    if (prevHadIssues && currentPassing) {
      newPassing.push(control.controlId);
    } else if (!prevHadIssues && !currentPassing) {
      newFailing.push(control.controlId);
    } else {
      unchanged.push(control.controlId);
    }
  }

  return { newPassing, newFailing, unchanged };
}
