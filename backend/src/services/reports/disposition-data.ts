/**
 * Canonical disposition data for a scan.
 *
 * "Disposition" = anything that explains why a finding or scanner is NOT in the
 * live open-issues stream. This is the audit evidence that turns a scan report
 * into something a compliance auditor (or coding agent) can act on:
 *
 *   - skippedScanners[]   — scanners that did not run, with reason + hint
 *   - dismissedFindings[] — findings closed as fixed/ignored/false_positive/deferred
 *   - autoSuppressedRules[] — finding_suppressions that auto-closed findings on this scan
 *   - summary             — counts per disposition for overview UIs
 *
 * Used by: markdown-generator, sarif-generator, JSON scan_detail report,
 *          and GET /api/v1/scans/:id/dispositions.
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';

export type FindingDisposition = 'fixed' | 'ignored' | 'false_positive' | 'deferred';

export interface SkippedScanner {
  scanner: string;
  skipReason: string | null;
  skipHint: string | null;
  duration: number;
}

export interface DismissedFinding {
  id: string;
  scanner: string;
  ruleId: string | null;
  severity: string;
  title: string;
  filePath: string | null;
  lineNumber: number | null;
  cweId: string | null;
  owaspCategory: string | null;
  status: FindingDisposition;
  dismissedReason: string | null;
  dismissedComment: string | null;
  dismissedBy: { id: string; email: string | null; name: string | null } | null;
  dismissedAt: string | null;
  /** ID of the suppression rule that auto-applied this disposition (if any) */
  suppressionRuleId: string | null;
}

export interface AutoSuppressionRuleApplied {
  ruleId: string;
  matchType: 'rule_id' | 'scanner' | 'cwe' | 'title_pattern';
  matchValue: string;
  targetStatus: FindingDisposition;
  reason: string | null;
  comment: string | null;
  matchedFindingsCount: number;
  createdAt: string;
}

export interface DispositionSummary {
  skippedScannerCount: number;
  totalDismissed: number;
  byStatus: Record<FindingDisposition, number>;
  autoSuppressedCount: number;
  manuallyDismissedCount: number;
  rulesAppliedCount: number;
}

export interface ScanDispositions {
  scanId: string;
  generatedAt: string;
  skippedScanners: SkippedScanner[];
  dismissedFindings: DismissedFinding[];
  autoSuppressedRules: AutoSuppressionRuleApplied[];
  summary: DispositionSummary;
}

const DISPOSITION_STATUSES: FindingDisposition[] = ['fixed', 'ignored', 'false_positive', 'deferred'];

/**
 * Fetch all disposition data for a scan in a single round-trip set.
 *
 * Caller is responsible for verifying scan ownership beforehand (this function
 * trusts that scanId is one the user is allowed to read).
 */
export async function getScanDispositions(scanId: string): Promise<ScanDispositions> {
  const [scanRow, dismissedRows, scanProjectRow] = await Promise.all([
    db.execute(sql`SELECT scanners_executed FROM scans WHERE id = ${scanId}`),
    db.execute(sql`
      SELECT
        f.id,
        COALESCE(f.tool_name, f.scanner) AS scanner,
        f.rule_id,
        f.severity,
        f.title,
        f.file_path,
        f.line_number,
        f.cwe_id,
        f.owasp_category,
        f.status,
        f.dismissed_reason,
        f.dismissed_comment,
        f.dismissed_at,
        f.dismissed_by,
        u.email AS dismissed_by_email,
        u.name AS dismissed_by_name
      FROM findings f
      LEFT JOIN users u ON u.id = f.dismissed_by
      WHERE f.scan_id = ${scanId}
        AND f.status IN ('fixed', 'ignored', 'false_positive', 'deferred')
      ORDER BY
        CASE f.status
          WHEN 'false_positive' THEN 1
          WHEN 'deferred' THEN 2
          WHEN 'ignored' THEN 3
          WHEN 'fixed' THEN 4
        END,
        CASE f.severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        f.dismissed_at DESC NULLS LAST
    `),
    db.execute(sql`SELECT project_id FROM scans WHERE id = ${scanId}`),
  ]);

  if (scanRow.rows.length === 0) {
    throw new Error(`Scan ${scanId} not found`);
  }

  const projectId = (scanProjectRow.rows[0] as Record<string, unknown> | undefined)?.project_id as string | undefined;

  // 1. Skipped scanners — read from scanners_executed JSONB on the scan
  const scannersExecutedRaw = (scanRow.rows[0] as Record<string, unknown>).scanners_executed;
  const scannersExecuted: Array<{
    scanner: string;
    success?: boolean;
    skipped?: boolean;
    skipReason?: string | null;
    skipHint?: string | null;
    duration?: number;
  }> = parseScannersExecuted(scannersExecutedRaw);

  const skippedScanners: SkippedScanner[] = scannersExecuted
    .filter(s => s.skipped && !s.scanner.startsWith('_'))
    .map(s => ({
      scanner: s.scanner,
      skipReason: s.skipReason ?? null,
      skipHint: s.skipHint ?? null,
      duration: s.duration ?? 0,
    }))
    .sort((a, b) => a.scanner.localeCompare(b.scanner));

  // 2. Dismissed findings + which auto-suppression rule (if any) matched each one.
  // We resolve this in-memory rather than via a SQL join because there's no
  // foreign key from finding -> suppression_rule; matching is rule-based.
  let activeRules: Array<{
    id: string;
    match_type: 'rule_id' | 'scanner' | 'cwe' | 'title_pattern';
    match_value: string;
    target_status: FindingDisposition;
    reason: string | null;
    comment: string | null;
    created_at: string;
  }> = [];

  if (projectId) {
    const ruleRows = await db.execute(sql`
      SELECT id, match_type, match_value, target_status, reason, comment, created_at
      FROM finding_suppressions
      WHERE project_id = ${projectId} AND is_active = true
    `);
    activeRules = ruleRows.rows as typeof activeRules;
  }

  const dismissedFindings: DismissedFinding[] = dismissedRows.rows.map(rawRow => {
    const r = rawRow as Record<string, unknown>;
    const status = r.status as FindingDisposition;
    const matchedRule = matchSuppressionRule(
      {
        scanner: r.scanner as string,
        ruleId: (r.rule_id as string) || null,
        cweId: (r.cwe_id as string) || null,
        title: (r.title as string) || '',
      },
      activeRules.filter(rule => rule.target_status === status),
    );

    const dismissedBy = r.dismissed_by
      ? {
          id: r.dismissed_by as string,
          email: (r.dismissed_by_email as string) || null,
          name: (r.dismissed_by_name as string) || null,
        }
      : null;

    return {
      id: r.id as string,
      scanner: (r.scanner as string) || 'unknown',
      ruleId: (r.rule_id as string) || null,
      severity: (r.severity as string) || 'info',
      title: (r.title as string) || '',
      filePath: (r.file_path as string) || null,
      lineNumber: (r.line_number as number) ?? null,
      cweId: (r.cwe_id as string) || null,
      owaspCategory: (r.owasp_category as string) || null,
      status,
      dismissedReason: (r.dismissed_reason as string) || null,
      dismissedComment: (r.dismissed_comment as string) || null,
      dismissedBy,
      dismissedAt: r.dismissed_at ? new Date(r.dismissed_at as string).toISOString() : null,
      suppressionRuleId: matchedRule?.id ?? null,
    };
  });

  // 3. Aggregate which suppression rules actually matched on this scan
  const ruleMatchCounts = new Map<string, number>();
  for (const f of dismissedFindings) {
    if (f.suppressionRuleId) {
      ruleMatchCounts.set(f.suppressionRuleId, (ruleMatchCounts.get(f.suppressionRuleId) ?? 0) + 1);
    }
  }

  const autoSuppressedRules: AutoSuppressionRuleApplied[] = activeRules
    .filter(r => ruleMatchCounts.has(r.id))
    .map(r => ({
      ruleId: r.id,
      matchType: r.match_type,
      matchValue: r.match_value,
      targetStatus: r.target_status,
      reason: r.reason,
      comment: r.comment,
      matchedFindingsCount: ruleMatchCounts.get(r.id) ?? 0,
      createdAt: new Date(r.created_at).toISOString(),
    }))
    .sort((a, b) => b.matchedFindingsCount - a.matchedFindingsCount);

  // 4. Summary counts
  const byStatus = DISPOSITION_STATUSES.reduce<Record<FindingDisposition, number>>((acc, s) => {
    acc[s] = 0;
    return acc;
  }, { fixed: 0, ignored: 0, false_positive: 0, deferred: 0 });
  let autoSuppressedCount = 0;
  let manuallyDismissedCount = 0;
  for (const f of dismissedFindings) {
    byStatus[f.status]++;
    if (f.suppressionRuleId) autoSuppressedCount++;
    else manuallyDismissedCount++;
  }

  return {
    scanId,
    generatedAt: new Date().toISOString(),
    skippedScanners,
    dismissedFindings,
    autoSuppressedRules,
    summary: {
      skippedScannerCount: skippedScanners.length,
      totalDismissed: dismissedFindings.length,
      byStatus,
      autoSuppressedCount,
      manuallyDismissedCount,
      rulesAppliedCount: autoSuppressedRules.length,
    },
  };
}

function parseScannersExecuted(raw: unknown): Array<{
  scanner: string;
  success?: boolean;
  skipped?: boolean;
  skipReason?: string | null;
  skipHint?: string | null;
  duration?: number;
}> {
  if (!raw) return [];
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  return Array.isArray(parsed) ? parsed : [];
}

function matchSuppressionRule(
  finding: { scanner: string; ruleId: string | null; cweId: string | null; title: string },
  rules: Array<{ id: string; match_type: string; match_value: string }>,
): { id: string } | null {
  for (const rule of rules) {
    switch (rule.match_type) {
      case 'rule_id':
        if (finding.ruleId && finding.ruleId === rule.match_value) return { id: rule.id };
        break;
      case 'scanner':
        if (finding.scanner === rule.match_value) return { id: rule.id };
        break;
      case 'cwe':
        if (finding.cweId && finding.cweId === rule.match_value) return { id: rule.id };
        break;
      case 'title_pattern':
        if (finding.title.toLowerCase().includes(rule.match_value.toLowerCase())) return { id: rule.id };
        break;
    }
  }
  return null;
}
