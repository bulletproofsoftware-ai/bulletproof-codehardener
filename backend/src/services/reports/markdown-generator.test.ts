import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateMarkdownReport, escapeMarkdownField, neutralizeFences } from './markdown-generator.js';

const mockExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: { execute: (...args: unknown[]) => mockExecute(...args) },
}));
vi.mock('drizzle-orm', () => {
  const sqlFn: any = (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' });
  sqlFn.raw = (s: string) => ({ strings: [s] as unknown as TemplateStringsArray, values: [], _tag: 'sql-raw' });
  return { sql: sqlFn };
});

interface MockOpts {
  scan?: Record<string, unknown> | null;
  openFindings?: Record<string, unknown>[];
  scannersExecuted?: unknown;
  dismissedRows?: Record<string, unknown>[];
  projectId?: string;
  suppressionRules?: Record<string, unknown>[];
  candidatePatches?: Record<string, unknown>[];
  threatsJson?: string | null;
}

function setupMock(opts: MockOpts = {}) {
  mockExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
    const sql = q.strings.join(' ');
    if (sql.includes('FROM candidate_patches cp')) {
      return Promise.resolve({ rows: opts.candidatePatches ?? [] });
    }
    if (sql.includes('JOIN threat_models tm')) {
      return Promise.resolve({ rows: opts.threatsJson != null ? [{ threats_json: opts.threatsJson }] : [] });
    }
    if (sql.includes('FROM scans s\n    JOIN projects p')) {
      // Top-level scan metadata fetch
      return Promise.resolve({
        rows: opts.scan ? [opts.scan] : [],
      });
    }
    if (sql.includes('SELECT * FROM findings')) {
      return Promise.resolve({ rows: opts.openFindings ?? [] });
    }
    if (sql.includes('SELECT scanners_executed FROM scans')) {
      return Promise.resolve({ rows: [{ scanners_executed: opts.scannersExecuted ?? null }] });
    }
    if (sql.includes('AND f.status IN')) {
      return Promise.resolve({ rows: opts.dismissedRows ?? [] });
    }
    if (sql.includes('SELECT project_id FROM scans')) {
      return Promise.resolve({ rows: [{ project_id: opts.projectId ?? 'p1' }] });
    }
    if (sql.includes('FROM finding_suppressions')) {
      return Promise.resolve({ rows: opts.suppressionRules ?? [] });
    }
    return Promise.resolve({ rows: [] });
  });
}

const baseScan = {
  id: 'scan-1',
  project_name: 'demo',
  branch: 'main',
  commit_sha: 'abc1234',
  profile: 'standard',
  score: 850,
  quality_level: 'good',
  completed_at: new Date('2026-05-01T10:00:00Z'),
  created_at: new Date('2026-05-01T09:55:00Z'),
  findings_count: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
  scanners_executed: null,
};

describe('Markdown report — disposition appendix', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders nothing extra when there are no dispositions', async () => {
    setupMock({ scan: baseScan, openFindings: [], projectId: 'p1' });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).not.toContain('Suppressed & Dismissed Findings');
    expect(md).not.toContain('Skipped Scanners');
    expect(md).not.toContain('Suppression Rules Applied');
  });

  it('lists skipped scanners with reason and hint', async () => {
    setupMock({
      scan: { ...baseScan, scanners_executed: [
        { scanner: 'zap', skipped: true, skipReason: 'no_target_url', skipHint: 'Set targetUrl', findings: 0, duration: 0 },
      ] },
      openFindings: [],
      scannersExecuted: [
        { scanner: 'zap', skipped: true, skipReason: 'no_target_url', skipHint: 'Set targetUrl', findings: 0, duration: 0 },
      ],
      projectId: 'p1',
    });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## Skipped Scanners (1)');
    expect(md).toContain('`zap`');
    expect(md).toContain('no_target_url');
    expect(md).toContain('Set targetUrl');
    // Inline note about skipped scanners
    expect(md).toContain('1 scanner(s) were skipped');
  });

  it('renders dismissed findings grouped by disposition with provenance', async () => {
    setupMock({
      scan: baseScan,
      openFindings: [],
      projectId: 'p1',
      dismissedRows: [
        {
          id: 'f-1', scanner: 'bandit', rule_id: 'B101', severity: 'medium',
          title: 'assert in test', file_path: 'tests/x.py', line_number: 12,
          cwe_id: null, owasp_category: null, status: 'false_positive',
          dismissed_reason: 'pytest fixture', dismissed_comment: null,
          dismissed_at: '2026-05-01T11:00:00Z',
          dismissed_by: 'u-1', dismissed_by_email: 'alice@example.com', dismissed_by_name: 'Alice',
        },
        {
          id: 'f-2', scanner: 'gosec', rule_id: 'G104', severity: 'low',
          title: 'unhandled error', file_path: 'main.go', line_number: 33,
          cwe_id: null, owasp_category: null, status: 'deferred',
          dismissed_reason: 'Q3 backlog', dismissed_comment: 'JIRA-123',
          dismissed_at: '2026-05-01T11:30:00Z',
          dismissed_by: null, dismissed_by_email: null, dismissed_by_name: null,
        },
      ],
    });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## Suppressed & Dismissed Findings (2)');
    expect(md).toContain('### False Positives (1)');
    expect(md).toContain('### Accepted (Deferred) (1)');
    expect(md).toContain('Alice');
    expect(md).toContain('pytest fixture');
    expect(md).toContain('JIRA-123'); // comment surfaced
    expect(md).toContain('Manually dismissed');
  });

  it('lists suppression rules that fired with match counts', async () => {
    setupMock({
      scan: baseScan,
      openFindings: [],
      projectId: 'p1',
      dismissedRows: [
        {
          id: 'f-1', scanner: 'bandit', rule_id: 'B101', severity: 'medium',
          title: 'assert', file_path: 'a.py', line_number: 1,
          cwe_id: null, owasp_category: null, status: 'false_positive',
          dismissed_reason: null, dismissed_comment: null, dismissed_at: null,
          dismissed_by: null, dismissed_by_email: null, dismissed_by_name: null,
        },
        {
          id: 'f-2', scanner: 'bandit', rule_id: 'B101', severity: 'medium',
          title: 'assert', file_path: 'b.py', line_number: 1,
          cwe_id: null, owasp_category: null, status: 'false_positive',
          dismissed_reason: null, dismissed_comment: null, dismissed_at: null,
          dismissed_by: null, dismissed_by_email: null, dismissed_by_name: null,
        },
      ],
      suppressionRules: [
        {
          id: 'rule-1234abcd', match_type: 'rule_id', match_value: 'B101',
          target_status: 'false_positive', reason: 'Asserts in tests are intentional', comment: null,
          created_at: '2026-04-01T00:00:00Z',
        },
      ],
    });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## Suppression Rules Applied (1)');
    expect(md).toContain('rule_id=`B101`');
    expect(md).toContain('| 2 |'); // matched count
    expect(md).toContain('Asserts in tests are intentional');
    expect(md).toContain('Auto-suppressed by rule');
  });

  it('open severity counts exclude dismissed findings', async () => {
    // Set up: 2 high open findings + 1 high dismissed. Should show "High Findings (2)".
    setupMock({
      scan: { ...baseScan, findings_count: { critical: 0, high: 2, medium: 0, low: 0, info: 0, total: 2 } },
      openFindings: [
        { id: 'o-1', severity: 'high', title: 'Open #1', scanner: 'bandit', rule_id: 'B102', file_path: 'a.py', line_number: 1, description: '', metadata: {} },
        { id: 'o-2', severity: 'high', title: 'Open #2', scanner: 'bandit', rule_id: 'B103', file_path: 'b.py', line_number: 2, description: '', metadata: {} },
      ],
      projectId: 'p1',
      dismissedRows: [{
        id: 'd-1', scanner: 'bandit', rule_id: 'B104', severity: 'high',
        title: 'Closed', file_path: 'c.py', line_number: 3,
        cwe_id: null, owasp_category: null, status: 'fixed',
        dismissed_reason: null, dismissed_comment: null, dismissed_at: null,
        dismissed_by: null, dismissed_by_email: null, dismissed_by_name: null,
      }],
    });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## High Findings (2)');
    expect(md).toContain('1 additional finding(s) excluded');
    expect(md).toContain('1 fixed');
  });
});

describe('escapeMarkdownField (§11 B1)', () => {
  it('escapes pipes, backticks, brackets, and angle brackets', () => {
    const out = escapeMarkdownField('a | b `c` [d] <script>');
    expect(out).toContain('\\|');
    expect(out).toContain('\\`');
    expect(out).toContain('\\[');
    expect(out).toContain('\\]');
    expect(out).toContain('&lt;');
    expect(out).toContain('&gt;');
    expect(out).not.toContain('<script>');
  });

  it('neutralizes leading block markers (#, >, -, *)', () => {
    expect(escapeMarkdownField('# forged heading')).toMatch(/^\\#/);
    // A leading `>` is both backslash-escaped and HTML-encoded → fully inert.
    expect(escapeMarkdownField('> forged quote')).toMatch(/^\\&gt;/);
    expect(escapeMarkdownField('- forged list')).toMatch(/^\\-/);
  });

  it('handles null/undefined', () => {
    expect(escapeMarkdownField(null)).toBe('');
    expect(escapeMarkdownField(undefined)).toBe('');
  });

  it('round-trips a literal pipe so a threat value stays in one table cell (F14)', () => {
    // After F10 the parser unescapes `\|` to a literal `|`; the renderer must
    // re-escape it so a threat title like `bypass A | B check` does not split
    // the rendered markdown table cell into two columns.
    const rendered = escapeMarkdownField('bypass A | B check');
    expect(rendered).toBe('bypass A \\| B check');
    // The rendered cell has exactly zero UNescaped pipes (all are `\|`).
    expect(rendered.split(/(?<!\\)\|/)).toHaveLength(1);
  });
});

describe('neutralizeFences (§11 B1)', () => {
  it('breaks embedded triple-backtick fences', () => {
    const out = neutralizeFences('safe\n```bash\nrm -rf /\n```\nmore');
    expect(out).not.toContain('```');
  });
});

describe('Candidate Patches section', () => {
  beforeEach(() => vi.clearAllMocks());

  it('omits the section when there are no patches', async () => {
    setupMock({ scan: baseScan, openFindings: [], projectId: 'p1' });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).not.toContain('Candidate Patches (LLM-generated)');
  });

  it('renders the banner and a fenced diff when patches exist', async () => {
    setupMock({
      scan: baseScan,
      openFindings: [],
      projectId: 'p1',
      candidatePatches: [{
        finding_title: 'SQLi in `getUser`',
        file_path: 'src/db.ts',
        line_number: 10,
        patch_diff: '--- a/src/db.ts\n+++ b/src/db.ts\n@@\n-bad\n+good\n```injected',
        rationale: 'Parameterize | the query',
        validation_notes: '# builds: yes',
      }],
    });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## Candidate Patches (LLM-generated)');
    expect(md).toContain('authored by an LLM');
    expect(md).toContain('never auto-applied');
    expect(md).toContain('```diff');
    expect(md).toContain('Validation notes (LLM self-assessment, unverified):');
    // Embedded fence inside the diff was neutralized (no stray closing fence breakout).
    expect(md).not.toContain('```injected');
    // Title/rationale/notes escaped.
    expect(md).toContain('\\`getUser\\`');
    expect(md).toContain('Parameterize \\| the query');
    expect(md).toMatch(/\\# builds: yes/);
  });
});

describe('Threat Model Summary section', () => {
  beforeEach(() => vi.clearAllMocks());

  it('omits the section when no threat model exists', async () => {
    setupMock({ scan: baseScan, openFindings: [], projectId: 'p1', threatsJson: null });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).not.toContain('Threat Model Summary');
  });

  it('renders escaped threat content and stores malicious markdown inertly', async () => {
    const threats = JSON.stringify([
      {
        id: 'T1',
        title: '# pwn | `code` <img>',
        actor: 'remote_unauth',
        surface: 'login | endpoint',
        asset: 'accounts',
        impact: 'critical',
        likelihood: 'likely',
        status: 'unmitigated',
        controls: 'none',
        evidence: '```break',
      },
    ]);
    setupMock({ scan: baseScan, openFindings: [], projectId: 'p1', threatsJson: threats });
    const md = await generateMarkdownReport({ scanId: 'scan-1', userId: 'u1' });
    expect(md).toContain('## Threat Model Summary');
    expect(md).toContain('### Top Unmitigated Threats');
    expect(md).toContain('unmitigated');
    // Malicious markdown is inert: leading # escaped, pipe/backtick escaped, angle bracket encoded.
    expect(md).toContain('\\# pwn');     // leading-heading neutralized
    expect(md).toContain('\\| \\`code\\`'); // pipe + backticks escaped
    expect(md).toContain('&lt;img&gt;');  // angle brackets encoded
    expect(md).not.toContain('| # pwn |'); // never rendered as a live table cell heading
  });
});
