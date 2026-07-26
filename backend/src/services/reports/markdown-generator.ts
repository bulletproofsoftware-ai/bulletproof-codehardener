import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { getScanDispositions, type ScanDispositions, type DismissedFinding, type FindingDisposition } from './disposition-data.js';
import type { ParsedThreat } from '../../types/index.js';

// ─── §11 B1: markdown-injection defense for LLM-sourced fields ────────────────

/**
 * Escape markdown control characters in an LLM/scan-sourced string so attacker
 * content embedded in a finding cannot break out of its cell/inline context or
 * forge structure (spec §11 B1). Escapes `|`, backticks, `[`, `]`, `<`, `>` and
 * neutralizes leading block markers (#, >, -, *).
 */
export function escapeMarkdownField(s: string | null | undefined): string {
  if (s == null) return '';
  let out = String(s)
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\|/g, '\\|')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]');
  // Neutralize leading line markers (#, >, -, *) that would forge headings/quotes/lists.
  // Done BEFORE angle-bracket encoding so a leading `>` is backslash-escaped here.
  out = out.replace(/^(\s*)([#>\-*]+)/gm, (_m, ws: string, marks: string) => `${ws}${marks.replace(/[#>\-*]/g, (c) => '\\' + c)}`);
  // Encode angle brackets last so HTML/JSX cannot be injected.
  out = out.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return out;
}

/**
 * Flatten a scanner-supplied string into something safe to truncate and drop
 * into a single table cell: collapse every whitespace run (including newlines,
 * which would otherwise terminate the table row) to one space, then truncate.
 *
 * Truncation happens on the RAW text and must run BEFORE escapeMarkdownField,
 * never after: slicing escaped text can cut an escape sequence in half and
 * leave a dangling backslash that re-exposes the very character it was hiding.
 */
export function collapseToCell(s: string | null | undefined, maxLength: number): string {
  if (s == null) return '';
  return String(s).replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

/**
 * Break any embedded ``` fence sequences so attacker content inside a fenced
 * block cannot close the fence early and inject live markdown (spec §11 B1/R4).
 */
export function neutralizeFences(s: string | null | undefined): string {
  if (s == null) return '';
  // Insert a zero-width space between backticks of any run of 3+ to break the fence.
  return String(s).replace(/`{3,}/g, (m) => m.split('').join('​'));
}

/** A finding is LLM-stage if produced by an LLM scanner or carries a stage/triage marker. */
function isLlmStageFinding(f: { scanner?: string; tool_name?: string; metadata?: unknown }): boolean {
  const scanner = (f.tool_name as string) || (f.scanner as string) || '';
  if (scanner === 'llm-vuln-scan' || scanner === 'llm-threatmodel') return true;
  const metadata = typeof f.metadata === 'string' ? safeJsonParse(f.metadata) : (f.metadata as Record<string, unknown> | undefined);
  if (!metadata) return false;
  return metadata.stage === 'vuln-scan' || metadata.stage === 'threat-model' || metadata.triage != null;
}

function safeJsonParse(s: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

export interface MarkdownReportOptions {
  scanId: string;
  userId: string;
  includeInfo?: boolean;       // include info-severity findings (default false)
  maxFindingsPerSeverity?: number;  // default 50
  minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export async function generateMarkdownReport(options: MarkdownReportOptions): Promise<string> {
  const { scanId, userId, includeInfo = false, maxFindingsPerSeverity = 50, minSeverity } = options;

  // 1. Fetch scan metadata
  const scanResult = await db.execute(sql`
    SELECT s.*, p.name as project_name, p.repo_url
    FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE s.id = ${scanId}
    AND p.user_id = ${userId}
  `);

  if (scanResult.rows.length === 0) {
    throw new Error('Scan not found');
  }

  const scan = scanResult.rows[0] as any;

  // 2. Fetch open findings ordered by severity (suppressed/dismissed shown in appendix)
  const severityFilter = minSeverity ? getSeverityFilter(minSeverity) : (includeInfo ? [] : ['info']);

  const [findingsResult, dispositions] = await Promise.all([
    db.execute(sql`
      SELECT * FROM findings
      WHERE scan_id = ${scanId}
        AND status = 'open'
      ${severityFilter.length > 0 ? sql`AND severity NOT IN (${sql.raw(severityFilter.map(s => `'${s}'`).join(','))})` : sql``}
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          WHEN 'info' THEN 5
        END,
        created_at DESC
    `),
    getScanDispositions(scanId),
  ]);

  const findings = findingsResult.rows as any[];

  // 3. Build markdown
  const lines: string[] = [];

  // Header
  lines.push(`# Security Scan Report: ${scan.project_name}`);
  lines.push('');
  lines.push(`**Scan ID:** \`${scan.id}\``);
  lines.push(`**Date:** ${new Date(scan.completed_at || scan.created_at).toISOString()}`);
  lines.push(`**Score:** ${scan.score ?? 'N/A'}/1000 (${scan.quality_level || 'unknown'})`);
  lines.push(`**Branch:** ${scan.branch || 'N/A'} | **Commit:** \`${scan.commit_sha || 'N/A'}\``);
  lines.push(`**Profile:** ${scan.profile || 'standard'}`);
  lines.push('');

  // Summary table
  const counts = parseFindingsCount(scan.findings_count);
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High | ${counts.high} |`);
  lines.push(`| Medium | ${counts.medium} |`);
  lines.push(`| Low | ${counts.low} |`);
  lines.push(`| Info | ${counts.info} |`);
  lines.push(`| **Total (open)** | **${counts.total}** |`);
  lines.push('');

  // Disposition summary inline so the reader knows the live numbers exclude these
  const dispSummary = dispositions.summary;
  if (dispSummary.totalDismissed > 0 || dispSummary.skippedScannerCount > 0) {
    lines.push('> **Note:** The counts above reflect _open_ findings only.');
    if (dispSummary.totalDismissed > 0) {
      const parts: string[] = [];
      if (dispSummary.byStatus.false_positive > 0) parts.push(`${dispSummary.byStatus.false_positive} false positive`);
      if (dispSummary.byStatus.deferred > 0) parts.push(`${dispSummary.byStatus.deferred} accepted (deferred)`);
      if (dispSummary.byStatus.ignored > 0) parts.push(`${dispSummary.byStatus.ignored} ignored`);
      if (dispSummary.byStatus.fixed > 0) parts.push(`${dispSummary.byStatus.fixed} fixed`);
      lines.push(`> ${dispSummary.totalDismissed} additional finding(s) excluded — ${parts.join(', ')} — see "Suppressed & Dismissed Findings" below.`);
    }
    if (dispSummary.skippedScannerCount > 0) {
      lines.push(`> ${dispSummary.skippedScannerCount} scanner(s) were skipped — see "Skipped Scanners" below.`);
    }
    lines.push('');
  }

  // Scanners executed table
  const scanners = parseScannerExecuted(scan.scanners_executed);
  if (scanners.length > 0) {
    lines.push('## Scanners Executed');
    lines.push('');
    lines.push('| Scanner | Status | Findings | Duration | Notes |');
    lines.push('|---------|--------|----------|----------|-------|');
    for (const s of scanners) {
      const status = s.skipped ? 'skipped' : s.success ? 'pass' : 'fail';
      let notes = '';
      if (s.skipped && s.skipReason) {
        notes = `_skipped: ${escapeMarkdownField(collapseToCell(s.skipReason, 80))}_`;
      } else if (!s.success && !s.skipped && s.error) {
        notes = `_error: ${escapeMarkdownField(collapseToCell(s.error, 80))}_`;
      }
      lines.push(`| ${s.scanner} | ${status} | ${s.findings} | ${(s.duration / 1000).toFixed(1)}s | ${notes} |`);
    }
    lines.push('');
  }

  // Findings by severity
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    const severityFindings = findings.filter(f => f.severity === severity);
    if (severityFindings.length === 0) continue;
    if (severity === 'info' && !includeInfo) continue;

    lines.push(`## ${capitalize(severity)} Findings (${severityFindings.length})`);
    lines.push('');

    const displayFindings = severityFindings.slice(0, maxFindingsPerSeverity);

    if (severity === 'low' || severity === 'info') {
      // Condensed format for low/info
      for (const f of displayFindings) {
        const location = f.file_path ? `\`${f.file_path}${f.line_number ? ':' + f.line_number : ''}\`` : 'N/A';
        lines.push(`- **${f.rule_id || f.scanner}**: ${f.title} (${location})`);
      }
      lines.push('');
    } else {
      // Full detail for critical/high/medium
      for (const f of displayFindings) {
        lines.push(renderFinding(f, severity));
      }
    }

    if (severityFindings.length > maxFindingsPerSeverity) {
      lines.push(`> ... and ${severityFindings.length - maxFindingsPerSeverity} more ${severity} findings`);
      lines.push('');
    }
  }

  // Candidate Patches (LLM-generated) — joined to this scan's findings.
  const patchRows = await fetchCandidatePatches(scanId);
  if (patchRows.length > 0) {
    lines.push('## Candidate Patches (LLM-generated)');
    lines.push('');
    lines.push('> ⚠️ These candidate patches were authored by an LLM reading source code. They were NOT compiled, run, or re-attacked. Validation notes are LLM self-assessment, unverified. Patches are never auto-applied — review carefully before use.');
    lines.push('');
    for (const p of patchRows) {
      const location = p.filePath ? `\`${p.filePath}${p.lineNumber ? ':' + p.lineNumber : ''}\`` : '_(no file)_';
      lines.push(`### ${escapeMarkdownField(p.findingTitle)} — ${location}`);
      lines.push('');
      lines.push('```diff');
      lines.push(neutralizeFences(p.patchDiff));
      lines.push('```');
      lines.push('');
      if (p.rationale) {
        lines.push(`**Rationale:** ${escapeMarkdownField(p.rationale)}`);
        lines.push('');
      }
      if (p.validationNotes) {
        lines.push(`**Validation notes (LLM self-assessment, unverified):** ${escapeMarkdownField(p.validationNotes)}`);
        lines.push('');
      }
      lines.push('---');
      lines.push('');
    }
  }

  // Threat Model Summary — rendered from parsed threats_json fields (never raw markdown; §11 B1).
  const threatModel = await fetchThreatModel(scanId);
  if (threatModel) {
    lines.push(...renderThreatModelSummary(threatModel));
  }

  // Appendix: Skipped Scanners
  if (dispositions.skippedScanners.length > 0) {
    lines.push(`## Skipped Scanners (${dispositions.skippedScanners.length})`);
    lines.push('');
    lines.push('Scanners that did not run on this scan, with the reason why and how to enable them.');
    lines.push('');
    lines.push('| Scanner | Reason | How to enable |');
    lines.push('|---------|--------|---------------|');
    for (const s of dispositions.skippedScanners) {
      lines.push(`| \`${s.scanner}\` | ${s.skipReason || 'unknown'} | ${s.skipHint || '_(no hint)_'} |`);
    }
    lines.push('');
  }

  // Appendix: Suppressed & Dismissed Findings
  if (dispositions.dismissedFindings.length > 0) {
    lines.push(`## Suppressed & Dismissed Findings (${dispositions.dismissedFindings.length})`);
    lines.push('');
    lines.push('Findings that exist in this scan but are not counted as open. Each disposition is documented here for audit and compliance evidence.');
    lines.push('');
    const dispositionLabels: Record<FindingDisposition, string> = {
      false_positive: 'False Positives',
      deferred: 'Accepted (Deferred)',
      ignored: 'Ignored',
      fixed: 'Fixed',
    };
    for (const status of ['false_positive', 'deferred', 'ignored', 'fixed'] as FindingDisposition[]) {
      const group = dispositions.dismissedFindings.filter(f => f.status === status);
      if (group.length === 0) continue;
      lines.push(`### ${dispositionLabels[status]} (${group.length})`);
      lines.push('');
      for (const f of group) {
        lines.push(renderDismissedFinding(f, dispositions));
      }
    }
  }

  // Appendix: Suppression Rules Applied
  if (dispositions.autoSuppressedRules.length > 0) {
    lines.push(`## Suppression Rules Applied (${dispositions.autoSuppressedRules.length})`);
    lines.push('');
    lines.push('Project-level suppression rules that auto-dismissed findings on this scan.');
    lines.push('');
    lines.push('| Rule ID | Match | Disposition | Findings | Reason |');
    lines.push('|---------|-------|-------------|----------|--------|');
    for (const r of dispositions.autoSuppressedRules) {
      const match = `${r.matchType}=\`${r.matchValue}\``;
      lines.push(`| \`${r.ruleId.slice(0, 8)}\` | ${match} | ${r.targetStatus} | ${r.matchedFindingsCount} | ${r.reason || '_(none)_'} |`);
    }
    lines.push('');
  }

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  const recommendations = generateRecommendations(findings);
  recommendations.forEach((rec, i) => {
    lines.push(`${i + 1}. ${rec}`);
  });
  lines.push('');

  // Footer
  lines.push('---');
  lines.push(`*Generated by Code Hardener v0.1.0 | ${new Date().toISOString()}*`);

  return lines.join('\n');
}

function renderFinding(f: any, severity: string): string {
  const lines: string[] = [];
  const tag = `[${severity.toUpperCase()}]`;
  // §11 B1 (conductor-approved): escape the title for ALL findings (defense in
  // depth — any scanner output can carry attacker content from scanned code).
  const title = escapeMarkdownField(f.description_simple || f.title);
  // LLM-stage findings get full escaping on free-text fields (description, fix).
  const llmStage = isLlmStageFinding(f);

  lines.push(`### ${tag} ${title}`);
  lines.push('');

  if (f.file_path) {
    lines.push(`- **File:** \`${f.file_path}${f.line_number ? ':' + f.line_number : ''}\``);
  }
  lines.push(`- **Scanner:** ${f.scanner || f.tool_name || 'unknown'}`);
  if (f.rule_id) lines.push(`- **Rule:** \`${f.rule_id}\``);
  if (f.cwe_id) lines.push(`- **CWE:** [${f.cwe_id}](https://cwe.mitre.org/data/definitions/${f.cwe_id.replace(/\D/g, '')}.html)`);
  if (f.owasp_category) lines.push(`- **OWASP:** ${f.owasp_category}`);
  lines.push('');

  // Description
  if (f.description && f.description !== f.title) {
    const desc = llmStage ? escapeMarkdownField(f.description) : f.description;
    lines.push(`**What's wrong:** ${desc}`);
    lines.push('');
  }

  // Code snippet — fence-neutralized inside a fenced block for ALL findings (§11 B1).
  if (f.code_snippet) {
    const lang = inferLanguage(f.file_path);
    lines.push('**Code:**');
    lines.push(`\`\`\`${lang}`);
    lines.push(neutralizeFences(f.code_snippet));
    lines.push('```');
    lines.push('');
  }

  // Fix guidance
  if (f.fix_description) {
    const fix = llmStage ? escapeMarkdownField(f.fix_description) : f.fix_description;
    lines.push(`**How to fix:** ${fix}`);
    lines.push('');
  }

  // Action from metadata
  const metadata = typeof f.metadata === 'string' ? JSON.parse(f.metadata) : f.metadata;
  if (metadata?.actionRequired) {
    const action = llmStage ? escapeMarkdownField(metadata.actionRequired) : metadata.actionRequired;
    lines.push(`**Action:** ${action}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  return lines.join('\n');
}

function inferLanguage(filePath: string | null): string {
  if (!filePath) return '';
  const ext = filePath.split('.').pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    ts: 'typescript', tsx: 'typescript', js: 'javascript', jsx: 'javascript',
    py: 'python', go: 'go', java: 'java', rb: 'ruby', rs: 'rust',
    php: 'php', cs: 'csharp', cpp: 'cpp', c: 'c', swift: 'swift',
    kt: 'kotlin', scala: 'scala', yaml: 'yaml', yml: 'yaml',
    json: 'json', xml: 'xml', sql: 'sql', sh: 'bash', bash: 'bash',
    tf: 'hcl', hcl: 'hcl', dockerfile: 'dockerfile',
  };
  return langMap[ext || ''] || '';
}

function parseFindingsCount(raw: any): { critical: number; high: number; medium: number; low: number; info: number; total: number } {
  if (!raw) return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  return {
    critical: parsed.critical || 0,
    high: parsed.high || 0,
    medium: parsed.medium || 0,
    low: parsed.low || 0,
    info: parsed.info || 0,
    total: parsed.total || 0,
  };
}

function parseScannerExecuted(raw: any): Array<{ scanner: string; success: boolean; skipped: boolean; skipReason?: string | null; skipHint?: string | null; findings: number; duration: number; error: string | null }> {
  if (!raw) return [];
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  return Array.isArray(parsed) ? parsed : [];
}

function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function getSeverityFilter(minSeverity: string): string[] {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const idx = order.indexOf(minSeverity);
  return idx >= 0 ? order.slice(idx + 1) : [];
}

function renderDismissedFinding(f: DismissedFinding, dispositions: ScanDispositions): string {
  const lines: string[] = [];
  const location = f.filePath ? `\`${f.filePath}${f.lineNumber ? ':' + f.lineNumber : ''}\`` : '_(no file)_';
  const sevTag = `[${f.severity.toUpperCase()}]`;

  lines.push(`#### ${sevTag} ${f.title}`);
  lines.push('');
  lines.push(`- **Scanner:** \`${f.scanner}\`${f.ruleId ? ` (rule \`${f.ruleId}\`)` : ''}`);
  lines.push(`- **Location:** ${location}`);
  if (f.cweId) lines.push(`- **CWE:** ${f.cweId}`);
  if (f.owaspCategory) lines.push(`- **OWASP:** ${f.owaspCategory}`);
  lines.push(`- **Disposition:** ${dispositionLabel(f.status)}`);
  lines.push(`- **Reason:** ${f.dismissedReason || '_(none provided)_'}`);
  if (f.dismissedComment) lines.push(`- **Comment:** ${f.dismissedComment}`);
  if (f.dismissedBy) {
    const who = f.dismissedBy.name || f.dismissedBy.email || f.dismissedBy.id;
    lines.push(`- **Dismissed by:** ${who}${f.dismissedAt ? ` on ${f.dismissedAt}` : ''}`);
  } else if (f.dismissedAt) {
    lines.push(`- **Dismissed at:** ${f.dismissedAt}`);
  }
  if (f.suppressionRuleId) {
    const rule = dispositions.autoSuppressedRules.find(r => r.ruleId === f.suppressionRuleId);
    if (rule) {
      lines.push(`- **Auto-suppressed by rule:** \`${rule.ruleId.slice(0, 8)}\` (${rule.matchType}=\`${rule.matchValue}\`)`);
    }
  } else {
    lines.push(`- **Source:** Manually dismissed`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');
  return lines.join('\n');
}

function dispositionLabel(s: FindingDisposition): string {
  switch (s) {
    case 'false_positive': return 'False Positive';
    case 'deferred': return 'Accepted (Deferred)';
    case 'ignored': return 'Ignored';
    case 'fixed': return 'Fixed';
  }
}

// ─── Candidate patches (LLM-generated) ────────────────────────────────────────

interface PatchRow {
  findingTitle: string;
  filePath: string | null;
  lineNumber: number | null;
  patchDiff: string;
  rationale: string;
  validationNotes: string;
}

async function fetchCandidatePatches(scanId: string): Promise<PatchRow[]> {
  const result = await db.execute(sql`
    SELECT cp.patch_diff, cp.rationale, cp.validation_notes,
           f.title AS finding_title, f.file_path, f.line_number
    FROM candidate_patches cp
    JOIN findings f ON f.id = cp.finding_id
    WHERE cp.scan_id = ${scanId}
    ORDER BY cp.created_at DESC
  `);
  return (result.rows as any[]).map((row) => ({
    findingTitle: (row.finding_title as string) ?? 'Finding',
    filePath: (row.file_path as string | null) ?? null,
    lineNumber: (row.line_number as number | null) ?? null,
    patchDiff: (row.patch_diff as string) ?? '',
    rationale: (row.rationale as string) ?? '',
    validationNotes: (row.validation_notes as string) ?? '',
  }));
}

// ─── Threat model summary (parsed threats_json only — §11 B1) ─────────────────

async function fetchThreatModel(scanId: string): Promise<ParsedThreat[] | null> {
  const result = await db.execute(sql`
    SELECT tm.threats_json
    FROM scans s
    JOIN threat_models tm ON tm.project_id = s.project_id
    WHERE s.id = ${scanId}
  `);
  if (result.rows.length === 0) return null;
  const raw = (result.rows[0] as Record<string, unknown>).threats_json;
  if (typeof raw !== 'string') return null;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ParsedThreat[]) : null;
  } catch {
    return null;
  }
}

function renderThreatModelSummary(threats: ParsedThreat[]): string[] {
  const lines: string[] = [];
  lines.push('## Threat Model Summary');
  lines.push('');

  // Counts by status and by impact.
  const byStatus: Record<string, number> = {};
  const byImpact: Record<string, number> = {};
  for (const t of threats) {
    byStatus[t.status] = (byStatus[t.status] ?? 0) + 1;
    byImpact[t.impact] = (byImpact[t.impact] ?? 0) + 1;
  }
  lines.push(`**Total threats modeled:** ${threats.length}`);
  lines.push('');
  lines.push('| Status | Count | | Impact | Count |');
  lines.push('|--------|-------|-|--------|-------|');
  const statusKeys = ['unmitigated', 'partially_mitigated', 'mitigated', 'risk_accepted'];
  const impactKeys = ['existential', 'critical', 'high', 'medium', 'low'];
  const rows = Math.max(statusKeys.length, impactKeys.length);
  for (let i = 0; i < rows; i++) {
    const sk = statusKeys[i];
    const ik = impactKeys[i];
    const sCell = sk ? `${sk} | ${byStatus[sk] ?? 0}` : ' | ';
    const iCell = ik ? `${ik} | ${byImpact[ik] ?? 0}` : ' | ';
    lines.push(`| ${sCell} | | ${iCell} |`);
  }
  lines.push('');

  // Top 5 unmitigated threats as an escaped table.
  const unmitigated = threats
    .filter((t) => t.status === 'unmitigated')
    .sort((a, b) => impactRank(a.impact) - impactRank(b.impact))
    .slice(0, 5);
  if (unmitigated.length > 0) {
    lines.push('### Top Unmitigated Threats');
    lines.push('');
    lines.push('| ID | Threat | Actor | Surface | Impact | Likelihood |');
    lines.push('|----|--------|-------|---------|--------|------------|');
    for (const t of unmitigated) {
      lines.push(
        `| ${escapeMarkdownField(t.id)} | ${escapeMarkdownField(t.title)} | ${escapeMarkdownField(t.actor)} | ` +
        `${escapeMarkdownField(t.surface)} | ${escapeMarkdownField(t.impact)} | ${escapeMarkdownField(t.likelihood)} |`,
      );
    }
    lines.push('');
  }
  return lines;
}

function impactRank(impact: string): number {
  const order = ['existential', 'critical', 'high', 'medium', 'low'];
  const idx = order.indexOf(impact);
  return idx < 0 ? order.length : idx;
}

function generateRecommendations(findings: any[]): string[] {
  const recs: string[] = [];
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const secretFindings = findings.filter(f => f.scanner === 'gitleaks');
  const depFindings = findings.filter(f => f.scanner === 'trivy' || f.scanner === 'grype');

  if (criticalCount > 0) recs.push(`**Immediately** address ${criticalCount} critical finding(s) -- these represent active exploitable vulnerabilities`);
  if (highCount > 0) recs.push(`Schedule remediation for ${highCount} high severity finding(s) within the current sprint`);
  if (secretFindings.length > 0) recs.push(`Rotate ${secretFindings.length} detected secret(s) and add them to .gitignore or environment variables`);
  if (depFindings.length > 0) recs.push(`Update ${depFindings.length} vulnerable dependency/dependencies -- run \`npm audit fix\` or equivalent`);
  if (findings.length === 0) recs.push('No findings detected -- maintain current security practices and scan regularly');

  return recs;
}
