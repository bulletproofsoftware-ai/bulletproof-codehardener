import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { getScanDispositions, type FindingDisposition } from './disposition-data.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: { name: string; version: string; rules: SarifRule[] } };
  invocations?: SarifInvocation[];
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: { tags?: string[] };
}

interface SarifSuppression {
  /**
   * SARIF 2.1.0 §3.35.3.
   * "inSource" = annotation in code (e.g. `# noqa`); we use it for auto-suppression rules.
   * "external" = the suppression lives outside source (manual UI dismissal).
   */
  kind: 'inSource' | 'external';
  /** Why this finding is suppressed — surfaced to auditors */
  justification?: string;
  /** Operator-supplied free-text comment */
  status?: 'accepted' | 'underReview' | 'rejected';
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
  fixes?: Array<{ description: { text: string } }>;
  suppressions?: SarifSuppression[];
  /**
   * SARIF 2.1.0 §3.27.10. baselineState = "absent" denotes a finding that has
   * been remediated (we use it for status='fixed').
   */
  baselineState?: 'new' | 'updated' | 'unchanged' | 'absent';
}

interface SarifInvocation {
  /** Per SARIF 2.1.0 §3.20.2. Required field. */
  executionSuccessful: boolean;
  toolExecutionNotifications?: Array<{
    descriptor: { id: string };
    level: 'note' | 'warning' | 'error';
    message: { text: string };
    properties?: Record<string, unknown>;
  }>;
}

export async function generateSarifReport(scanId: string, userId: string): Promise<SarifLog> {
  // Fetch ALL findings (open + dismissed) — SARIF spec requires us to keep
  // suppressed results in the run with a suppressions[] block, not drop them.
  const [findingsResult, dispositions] = await Promise.all([
    db.execute(sql`
      SELECT f.*, p.name as project_name
      FROM findings f
      JOIN scans s ON s.id = f.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE f.scan_id = ${scanId}
      AND p.user_id = ${userId}
      ORDER BY f.scanner, f.severity
    `),
    getScanDispositions(scanId),
  ]);

  const findings = findingsResult.rows as any[];

  // Build a quick lookup: finding.id -> dismissal info for suppressions[]
  const dismissedById = new Map(dispositions.dismissedFindings.map(d => [d.id, d]));

  // Group findings by scanner
  const byScanner = new Map<string, any[]>();
  for (const f of findings) {
    const scanner = f.scanner || f.tool_name || 'unknown';
    if (!byScanner.has(scanner)) byScanner.set(scanner, []);
    byScanner.get(scanner)!.push(f);
  }

  // Group skipped scanners alongside their tool entry — every scanner that
  // skipped gets its own SARIF run with an invocation that records why.
  const skippedByScanner = new Map(dispositions.skippedScanners.map(s => [s.scanner, s]));

  // Build SARIF runs: one per scanner that produced findings + one per
  // skipped scanner (so the report enumerates every tool that was considered)
  const runs: SarifRun[] = [];
  const seenScanners = new Set<string>();

  for (const [scanner, scannerFindings] of byScanner) {
    seenScanners.add(scanner);
    const rulesMap = new Map<string, SarifRule>();
    for (const f of scannerFindings) {
      const ruleId = f.rule_id || `${scanner}-finding`;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.title,
          shortDescription: { text: f.description || f.title },
          ...(f.cwe_id ? { helpUri: `https://cwe.mitre.org/data/definitions/${f.cwe_id.replace(/\D/g, '')}.html` } : {}),
          properties: {
            tags: [f.severity, ...(f.cwe_id ? [f.cwe_id] : []), ...(f.owasp_category ? [f.owasp_category] : [])],
          },
        });
      }
    }

    const results: SarifResult[] = scannerFindings.map((f: any) => {
      const dismissal = dismissedById.get(f.id);
      const result: SarifResult = {
        ruleId: f.rule_id || `${scanner}-finding`,
        level: severityToLevel(f.severity),
        message: { text: f.description_simple || f.description || f.title },
        ...(f.file_path ? {
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.file_path },
              ...(f.line_number ? { region: { startLine: f.line_number, ...(f.column_number ? { startColumn: f.column_number } : {}) } } : {}),
            },
          }],
        } : {}),
        ...(f.fix_description ? {
          fixes: [{ description: { text: f.fix_description } }],
        } : {}),
      };

      if (dismissal) {
        // Mark fixed findings via baselineState; mark the rest via suppressions[]
        if (dismissal.status === 'fixed') {
          result.baselineState = 'absent';
        }
        result.suppressions = [buildSuppression(dismissal)];
      }
      return result;
    });

    // If this scanner had skipped invocations recorded too, attach them
    const skip = skippedByScanner.get(scanner);
    const invocations: SarifInvocation[] | undefined = skip
      ? [{
          executionSuccessful: false,
          toolExecutionNotifications: [{
            descriptor: { id: `scanner.skipped` },
            level: 'note',
            message: { text: `Scanner skipped: ${skip.skipReason || 'unknown reason'}${skip.skipHint ? ` — ${skip.skipHint}` : ''}` },
            properties: {
              skipReason: skip.skipReason,
              skipHint: skip.skipHint,
            },
          }],
        }]
      : undefined;

    runs.push({
      tool: {
        driver: {
          name: `codehardener-${scanner}`,
          version: '0.1.0',
          rules: Array.from(rulesMap.values()),
        },
      },
      ...(invocations ? { invocations } : {}),
      results,
    });
  }

  // Skipped scanners that had NO findings still get a run entry so consumers
  // see every scanner that was considered, with the reason it skipped.
  for (const skip of dispositions.skippedScanners) {
    if (seenScanners.has(skip.scanner)) continue;
    runs.push({
      tool: {
        driver: {
          name: `codehardener-${skip.scanner}`,
          version: '0.1.0',
          rules: [],
        },
      },
      invocations: [{
        executionSuccessful: false,
        toolExecutionNotifications: [{
          descriptor: { id: `scanner.skipped` },
          level: 'note',
          message: { text: `Scanner skipped: ${skip.skipReason || 'unknown reason'}${skip.skipHint ? ` — ${skip.skipHint}` : ''}` },
          properties: {
            skipReason: skip.skipReason,
            skipHint: skip.skipHint,
          },
        }],
      }],
      results: [],
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  };
}

function buildSuppression(dismissal: {
  status: FindingDisposition;
  dismissedReason: string | null;
  dismissedComment: string | null;
  dismissedBy: { id: string; email: string | null; name: string | null } | null;
  dismissedAt: string | null;
  suppressionRuleId: string | null;
}): SarifSuppression {
  // Manual dismissals via the UI = "external"; auto-suppression rules = "inSource"
  // (the rule lives in project config, which acts as a source-level annotation).
  const kind: SarifSuppression['kind'] = dismissal.suppressionRuleId ? 'inSource' : 'external';

  // Map our disposition to a SARIF suppression status
  let status: SarifSuppression['status'] = 'accepted';
  if (dismissal.status === 'deferred') status = 'underReview';
  if (dismissal.status === 'false_positive') status = 'accepted';
  if (dismissal.status === 'ignored') status = 'accepted';
  if (dismissal.status === 'fixed') status = 'accepted';

  const justificationParts: string[] = [];
  justificationParts.push(`disposition=${dismissal.status}`);
  if (dismissal.dismissedReason) justificationParts.push(`reason=${dismissal.dismissedReason}`);
  if (dismissal.dismissedComment) justificationParts.push(`comment=${dismissal.dismissedComment}`);
  if (dismissal.dismissedBy) {
    const who = dismissal.dismissedBy.name || dismissal.dismissedBy.email || dismissal.dismissedBy.id;
    justificationParts.push(`by=${who}`);
  }
  if (dismissal.dismissedAt) justificationParts.push(`at=${dismissal.dismissedAt}`);

  return {
    kind,
    status,
    justification: justificationParts.join(' | '),
    properties: {
      disposition: dismissal.status,
      dismissedReason: dismissal.dismissedReason,
      dismissedComment: dismissal.dismissedComment,
      dismissedBy: dismissal.dismissedBy,
      dismissedAt: dismissal.dismissedAt,
      suppressionRuleId: dismissal.suppressionRuleId,
    },
  };
}

function severityToLevel(severity: string): 'error' | 'warning' | 'note' | 'none' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}
