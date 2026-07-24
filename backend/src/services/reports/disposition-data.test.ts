import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getScanDispositions } from './disposition-data.js';

const mockExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: { execute: (...args: unknown[]) => mockExecute(...args) },
}));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));

interface MockOpts {
  scannersExecuted?: unknown;
  dismissedRows?: Record<string, unknown>[];
  projectId?: string | null;
  suppressionRules?: Record<string, unknown>[];
  scanExists?: boolean;
}

function setupMock(opts: MockOpts = {}) {
  mockExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
    const sql = q.strings.join(' ');
    if (sql.includes('SELECT scanners_executed FROM scans')) {
      return Promise.resolve({
        rows: opts.scanExists === false ? [] : [{ scanners_executed: opts.scannersExecuted ?? null }],
      });
    }
    if (sql.includes('AND f.status IN')) {
      return Promise.resolve({ rows: opts.dismissedRows ?? [] });
    }
    if (sql.includes('SELECT project_id FROM scans')) {
      return Promise.resolve({
        rows: opts.projectId !== undefined && opts.projectId !== null ? [{ project_id: opts.projectId }] : [],
      });
    }
    if (sql.includes('FROM finding_suppressions')) {
      return Promise.resolve({ rows: opts.suppressionRules ?? [] });
    }
    return Promise.resolve({ rows: [] });
  });
}

function makeDismissed(overrides: Record<string, unknown> = {}) {
  return {
    id: 'f-1',
    scanner: 'bandit',
    rule_id: 'B101',
    severity: 'medium',
    title: 'Use of assert detected',
    file_path: 'app.py',
    line_number: 42,
    cwe_id: null,
    owasp_category: null,
    status: 'false_positive',
    dismissed_reason: 'Test code',
    dismissed_comment: null,
    dismissed_at: '2026-05-01T12:00:00Z',
    dismissed_by: null,
    dismissed_by_email: null,
    dismissed_by_name: null,
    ...overrides,
  };
}

describe('getScanDispositions', () => {
  beforeEach(() => vi.clearAllMocks());

  it('throws when the scan does not exist', async () => {
    setupMock({ scanExists: false });
    await expect(getScanDispositions('scan-x')).rejects.toThrow(/not found/);
  });

  it('returns empty arrays and zero counts for a clean scan', async () => {
    setupMock({ scannersExecuted: [], dismissedRows: [], projectId: 'p1', suppressionRules: [] });
    const r = await getScanDispositions('scan-1');
    expect(r.skippedScanners).toEqual([]);
    expect(r.dismissedFindings).toEqual([]);
    expect(r.autoSuppressedRules).toEqual([]);
    expect(r.summary.totalDismissed).toBe(0);
    expect(r.summary.skippedScannerCount).toBe(0);
  });

  it('extracts skipped scanners from scanners_executed JSONB', async () => {
    setupMock({
      scannersExecuted: [
        { scanner: 'zap', skipped: true, skipReason: 'no_target_url', skipHint: 'Set targetUrl', duration: 0 },
        { scanner: 'trivy', skipped: false, success: true, duration: 1500, findings: 2 },
        { scanner: 'nuclei', skipped: true, skipReason: 'target_unreachable', skipHint: null, duration: 100 },
        { scanner: '_file_inventory', skipped: false, duration: 50 }, // pseudo-scanner — must be filtered out
      ],
      projectId: 'p1',
    });
    const r = await getScanDispositions('scan-1');
    expect(r.skippedScanners.map(s => s.scanner)).toEqual(['nuclei', 'zap']);
    expect(r.skippedScanners[1].skipReason).toBe('no_target_url');
    expect(r.skippedScanners[1].skipHint).toBe('Set targetUrl');
    expect(r.summary.skippedScannerCount).toBe(2);
  });

  it('groups dismissed findings by status with full provenance', async () => {
    setupMock({
      projectId: 'p1',
      dismissedRows: [
        makeDismissed({
          id: 'f-1',
          status: 'false_positive',
          dismissed_reason: 'False positive — test fixture',
          dismissed_by: 'u-1',
          dismissed_by_email: 'alice@example.com',
          dismissed_by_name: 'Alice',
        }),
        makeDismissed({
          id: 'f-2',
          status: 'deferred',
          dismissed_reason: 'Will fix in Q3',
          dismissed_by: null,
        }),
        makeDismissed({ id: 'f-3', status: 'fixed' }),
        makeDismissed({ id: 'f-4', status: 'ignored' }),
      ],
    });
    const r = await getScanDispositions('scan-1');
    expect(r.summary.totalDismissed).toBe(4);
    expect(r.summary.byStatus).toEqual({ false_positive: 1, deferred: 1, ignored: 1, fixed: 1 });
    const fp = r.dismissedFindings.find(f => f.id === 'f-1')!;
    expect(fp.dismissedBy?.email).toBe('alice@example.com');
    expect(fp.dismissedReason).toContain('test fixture');
  });

  it('attributes findings to the matching auto-suppression rule', async () => {
    setupMock({
      projectId: 'p1',
      dismissedRows: [
        makeDismissed({ id: 'f-1', scanner: 'bandit', rule_id: 'B101', status: 'false_positive' }),
        makeDismissed({ id: 'f-2', scanner: 'bandit', rule_id: 'B101', status: 'false_positive' }),
        makeDismissed({ id: 'f-3', scanner: 'gosec', rule_id: 'G104', status: 'false_positive' }),
      ],
      suppressionRules: [
        {
          id: 'rule-1',
          match_type: 'rule_id',
          match_value: 'B101',
          target_status: 'false_positive',
          reason: 'Asserts in test files are intentional',
          comment: null,
          created_at: '2026-04-01T00:00:00Z',
        },
      ],
    });
    const r = await getScanDispositions('scan-1');
    expect(r.summary.autoSuppressedCount).toBe(2);
    expect(r.summary.manuallyDismissedCount).toBe(1);
    expect(r.autoSuppressedRules).toHaveLength(1);
    expect(r.autoSuppressedRules[0].matchedFindingsCount).toBe(2);
    const f1 = r.dismissedFindings.find(f => f.id === 'f-1')!;
    expect(f1.suppressionRuleId).toBe('rule-1');
    const f3 = r.dismissedFindings.find(f => f.id === 'f-3')!;
    expect(f3.suppressionRuleId).toBeNull();
  });

  it('only matches a rule when target_status equals the finding status', async () => {
    setupMock({
      projectId: 'p1',
      dismissedRows: [
        makeDismissed({ id: 'f-1', scanner: 'bandit', rule_id: 'B101', status: 'deferred' }),
      ],
      suppressionRules: [
        {
          id: 'rule-1',
          match_type: 'rule_id',
          match_value: 'B101',
          target_status: 'false_positive', // different target
          reason: null,
          comment: null,
          created_at: '2026-04-01T00:00:00Z',
        },
      ],
    });
    const r = await getScanDispositions('scan-1');
    // Rule does not apply because target_status differs from finding status.
    expect(r.dismissedFindings[0].suppressionRuleId).toBeNull();
    expect(r.summary.autoSuppressedCount).toBe(0);
    expect(r.summary.manuallyDismissedCount).toBe(1);
    expect(r.autoSuppressedRules).toHaveLength(0);
  });

  it('matches by scanner / cwe / title_pattern', async () => {
    setupMock({
      projectId: 'p1',
      dismissedRows: [
        makeDismissed({ id: 'f-1', scanner: 'noisy', rule_id: 'r1', status: 'ignored' }),
        makeDismissed({ id: 'f-2', cwe_id: 'CWE-79', status: 'ignored' }),
        makeDismissed({ id: 'f-3', title: 'Hardcoded test password in fixture', status: 'ignored' }),
      ],
      suppressionRules: [
        { id: 'r-scanner', match_type: 'scanner', match_value: 'noisy', target_status: 'ignored', reason: null, comment: null, created_at: '2026-04-01T00:00:00Z' },
        { id: 'r-cwe', match_type: 'cwe', match_value: 'CWE-79', target_status: 'ignored', reason: null, comment: null, created_at: '2026-04-01T00:00:00Z' },
        { id: 'r-title', match_type: 'title_pattern', match_value: 'test password', target_status: 'ignored', reason: null, comment: null, created_at: '2026-04-01T00:00:00Z' },
      ],
    });
    const r = await getScanDispositions('scan-1');
    expect(r.dismissedFindings.find(f => f.id === 'f-1')!.suppressionRuleId).toBe('r-scanner');
    expect(r.dismissedFindings.find(f => f.id === 'f-2')!.suppressionRuleId).toBe('r-cwe');
    expect(r.dismissedFindings.find(f => f.id === 'f-3')!.suppressionRuleId).toBe('r-title');
    expect(r.summary.rulesAppliedCount).toBe(3);
  });

  it('ignores leading-underscore pseudo-scanners in skipped count', async () => {
    setupMock({
      scannersExecuted: [
        { scanner: '_warmup', skipped: true, skipReason: 'noop' },
        { scanner: '_file_inventory', skipped: true, skipReason: 'noop' },
      ],
      projectId: 'p1',
    });
    const r = await getScanDispositions('scan-1');
    expect(r.skippedScanners).toHaveLength(0);
  });
});
