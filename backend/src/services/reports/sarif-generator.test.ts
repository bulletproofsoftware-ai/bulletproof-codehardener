import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateSarifReport } from './sarif-generator.js';

/**
 * The SARIF generator now makes multiple DB calls (findings + getScanDispositions
 * which queries scan, dismissed findings, project, and active suppression rules).
 * To keep the test setup ergonomic we route by inspecting the assembled SQL
 * template strings and returning the right rows for each query.
 */
function makeMockExecute(opts: {
  findings?: Record<string, unknown>[];
  scanRow?: { scanners_executed: unknown } | null;
  dismissedRows?: Record<string, unknown>[];
  scanProjectRow?: { project_id: string } | null;
  suppressionRules?: Record<string, unknown>[];
}) {
  return vi.fn((q: { strings: TemplateStringsArray }) => {
    const sql = q.strings.join(' ');
    if (sql.includes('FROM findings f') && sql.includes('JOIN scans')) {
      return Promise.resolve({ rows: opts.findings ?? [] });
    }
    if (sql.includes('SELECT scanners_executed FROM scans')) {
      return Promise.resolve({ rows: opts.scanRow !== undefined ? (opts.scanRow ? [opts.scanRow] : []) : [{ scanners_executed: null }] });
    }
    if (sql.includes('SELECT project_id FROM scans')) {
      return Promise.resolve({ rows: opts.scanProjectRow !== undefined ? (opts.scanProjectRow ? [opts.scanProjectRow] : []) : [] });
    }
    if (sql.includes('AND f.status IN')) {
      return Promise.resolve({ rows: opts.dismissedRows ?? [] });
    }
    if (sql.includes('FROM finding_suppressions')) {
      return Promise.resolve({ rows: opts.suppressionRules ?? [] });
    }
    return Promise.resolve({ rows: [] });
  });
}

const mockExecute = vi.fn();
vi.mock('../../db/client.js', () => ({
  db: {
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    strings,
    values,
    _tag: 'sql',
  }),
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function setupMock(findings: Record<string, unknown>[], extra: {
  dismissedRows?: Record<string, unknown>[];
  scanners_executed?: unknown;
  suppressionRules?: Record<string, unknown>[];
} = {}) {
  mockExecute.mockImplementation(makeMockExecute({
    findings,
    scanRow: { scanners_executed: extra.scanners_executed ?? null },
    scanProjectRow: { project_id: 'proj-1' },
    dismissedRows: extra.dismissedRows,
    suppressionRules: extra.suppressionRules,
  }));
}

function makeFindingRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'f-1',
    scan_id: 'scan-1',
    scanner: 'semgrep',
    tool_name: null,
    rule_id: 'security/sql-injection',
    severity: 'high',
    title: 'SQL Injection detected',
    description: 'User input concatenated into SQL query',
    description_simple: 'Attackers can manipulate your database',
    file_path: 'src/controllers/user.ts',
    line_number: 42,
    column_number: 10,
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021-Injection',
    fix_description: 'Use parameterized queries',
    project_name: 'test-project',
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('SARIF Generator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: scan exists with no skipped scanners and no dismissed findings.
    mockExecute.mockImplementation(makeMockExecute({
      findings: [makeFindingRow()],
      scanRow: { scanners_executed: null },
      scanProjectRow: { project_id: 'proj-1' },
    }));
  });

  it('generates valid SARIF 2.1.0 structure', async () => {
    mockExecute.mockImplementation(makeMockExecute({
      findings: [makeFindingRow()],
      scanRow: { scanners_executed: null },
      scanProjectRow: { project_id: 'proj-1' },
    }));

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.$schema).toContain('sarif-schema-2.1.0');
    expect(result.version).toBe('2.1.0');
    expect(result.runs).toBeDefined();
    expect(Array.isArray(result.runs)).toBe(true);
  });

  it('includes all findings as results', async () => {
    setupMock([
        makeFindingRow({ id: 'f-1', rule_id: 'rule-a', title: 'Finding A' }),
        makeFindingRow({ id: 'f-2', rule_id: 'rule-b', title: 'Finding B' }),
        makeFindingRow({ id: 'f-3', rule_id: 'rule-c', title: 'Finding C' }),
      ]);

    const result = await generateSarifReport('scan-1', 'user-1');

    const allResults = result.runs.flatMap(r => r.results);
    expect(allResults).toHaveLength(3);
  });

  it('maps severity to SARIF level correctly', async () => {
    setupMock([
        makeFindingRow({ id: 'f-1', severity: 'critical', rule_id: 'r1' }),
        makeFindingRow({ id: 'f-2', severity: 'high', rule_id: 'r2' }),
        makeFindingRow({ id: 'f-3', severity: 'medium', rule_id: 'r3' }),
        makeFindingRow({ id: 'f-4', severity: 'low', rule_id: 'r4' }),
        makeFindingRow({ id: 'f-5', severity: 'info', rule_id: 'r5' }),
      ]);

    const result = await generateSarifReport('scan-1', 'user-1');
    const results = result.runs[0].results;

    expect(results[0].level).toBe('error');     // critical
    expect(results[1].level).toBe('error');     // high
    expect(results[2].level).toBe('warning');   // medium
    expect(results[3].level).toBe('note');      // low
    expect(results[4].level).toBe('none');      // info
  });

  it('includes tool information with scanner name', async () => {
    setupMock([makeFindingRow({ scanner: 'trivy' })]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs[0].tool.driver.name).toBe('codehardener-trivy');
    expect(result.runs[0].tool.driver.version).toBe('0.1.0');
  });

  it('handles empty findings array', async () => {
    setupMock([]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs).toEqual([]);
    expect(result.version).toBe('2.1.0');
  });

  it('includes file path and line number in locations', async () => {
    setupMock([makeFindingRow({
        file_path: 'src/auth/login.ts',
        line_number: 55,
        column_number: 8,
      })]);

    const result = await generateSarifReport('scan-1', 'user-1');
    const location = result.runs[0].results[0].locations![0];

    expect(location.physicalLocation.artifactLocation.uri).toBe('src/auth/login.ts');
    expect(location.physicalLocation.region!.startLine).toBe(55);
    expect(location.physicalLocation.region!.startColumn).toBe(8);
  });

  it('omits locations when file_path is null', async () => {
    setupMock([makeFindingRow({ file_path: null, line_number: null })]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs[0].results[0].locations).toBeUndefined();
  });

  it('omits region when line_number is null', async () => {
    setupMock([makeFindingRow({ file_path: 'src/index.ts', line_number: null })]);

    const result = await generateSarifReport('scan-1', 'user-1');
    const location = result.runs[0].results[0].locations![0];

    expect(location.physicalLocation.artifactLocation.uri).toBe('src/index.ts');
    expect(location.physicalLocation.region).toBeUndefined();
  });

  it('groups findings by scanner into separate runs', async () => {
    setupMock([
        makeFindingRow({ id: 'f-1', scanner: 'semgrep', rule_id: 'r1' }),
        makeFindingRow({ id: 'f-2', scanner: 'semgrep', rule_id: 'r2' }),
        makeFindingRow({ id: 'f-3', scanner: 'trivy', rule_id: 'r3' }),
      ]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs).toHaveLength(2);

    const semgrepRun = result.runs.find(r => r.tool.driver.name === 'codehardener-semgrep');
    const trivyRun = result.runs.find(r => r.tool.driver.name === 'codehardener-trivy');

    expect(semgrepRun!.results).toHaveLength(2);
    expect(trivyRun!.results).toHaveLength(1);
  });

  it('builds unique rules from findings per scanner', async () => {
    setupMock([
        makeFindingRow({ id: 'f-1', rule_id: 'sql-injection', title: 'SQL Injection' }),
        makeFindingRow({ id: 'f-2', rule_id: 'sql-injection', title: 'SQL Injection' }), // duplicate rule
        makeFindingRow({ id: 'f-3', rule_id: 'xss', title: 'Cross-Site Scripting' }),
      ]);

    const result = await generateSarifReport('scan-1', 'user-1');
    const rules = result.runs[0].tool.driver.rules;

    expect(rules).toHaveLength(2); // sql-injection and xss, not 3
    expect(rules.map(r => r.id)).toContain('sql-injection');
    expect(rules.map(r => r.id)).toContain('xss');
  });

  it('includes CWE helpUri when cwe_id is present', async () => {
    setupMock([makeFindingRow({ cwe_id: 'CWE-89' })]);

    const result = await generateSarifReport('scan-1', 'user-1');
    const rule = result.runs[0].tool.driver.rules[0];

    expect(rule.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html');
  });

  it('includes fix descriptions when available', async () => {
    setupMock([makeFindingRow({ fix_description: 'Use parameterized queries instead of string concatenation' })]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs[0].results[0].fixes).toBeDefined();
    expect(result.runs[0].results[0].fixes![0].description.text).toContain('parameterized queries');
  });

  it('falls back to tool_name when scanner is null', async () => {
    setupMock([makeFindingRow({ scanner: null, tool_name: 'custom-scanner' })]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs[0].tool.driver.name).toBe('codehardener-custom-scanner');
  });

  it('uses description_simple for message text when available', async () => {
    setupMock([makeFindingRow({
        description: 'Technical jargon here',
        description_simple: 'Plain language explanation',
      })]);

    const result = await generateSarifReport('scan-1', 'user-1');

    expect(result.runs[0].results[0].message.text).toBe('Plain language explanation');
  });
});
