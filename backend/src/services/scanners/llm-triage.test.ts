import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockEnv = {
  ANTHROPIC_API_KEY: 'test-key' as string | undefined,
  LLM_THREATMODEL_MODEL: 'claude-haiku-test',
  LLM_TRIAGE_MAX_FINDINGS: 20,
  LLM_TRIAGE_VOTES: 3,
  LLM_SCAN_MAX_TOTAL_TOKENS: 500000,
};

vi.mock('../../config/env.js', () => ({
  get env() { return mockEnv; },
  get llmVerifyEnabled() { return !!mockEnv.ANTHROPIC_API_KEY; },
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

const dbExecute = vi.fn();
vi.mock('../../db/client.js', () => ({ db: { execute: (...a: unknown[]) => dbExecute(...a) } }));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));

// Mock the agent loop. Each call shifts the next queued verdict text.
const agentTexts: string[] = [];
const runBoundedAgent = vi.fn(async () => {
  const text = agentTexts.length ? agentTexts.shift()! : 'VERDICT: cannot_verify\nREASON: none';
  return { finalText: text, iterations: 1, stopReason: 'end_turn', inputTokens: 1, outputTokens: 1 };
});
let budgetExhausted = false;
vi.mock('./llm-agent.js', () => ({
  runBoundedAgent: (...a: unknown[]) => runBoundedAgent(...a),
  ScanTokenBudget: class {
    get exhausted() { return budgetExhausted; }
    consume() { return !budgetExhausted; }
    remaining() { return budgetExhausted ? 0 : 1000; }
  },
}));

import { runTriageStage } from './llm-triage.js';
import { ScanTokenBudget } from './llm-agent.js';

/** Capture every UPDATE so tests can assert what happened to each finding. */
interface Update { id: string; sql: string; status?: string; reason?: string; severity?: string; llmVerified?: boolean; metadata?: any }
let updates: Update[] = [];

function sqlText(q: { strings: TemplateStringsArray }): string {
  return q.strings.join(' ');
}

/**
 * Route db.execute. `candidates` are returned for the candidate query, `threats`
 * for the threat_models query. UPDATEs are recorded.
 */
function setupDb(candidates: any[], threatsJson: string | null = null) {
  updates = [];
  dbExecute.mockImplementation((q: { strings: TemplateStringsArray; values: unknown[] }) => {
    const t = sqlText(q);
    if (t.includes('llm_analysis_enabled AS enabled')) {
      return Promise.resolve({ rows: [{ enabled: true }] });
    }
    if (t.includes('FROM findings') && t.includes('scanner = \'llm-vuln-scan\'')) {
      return Promise.resolve({ rows: candidates });
    }
    if (t.includes('threats_json AS threats_json')) {
      return Promise.resolve({ rows: threatsJson != null ? [{ threats_json: threatsJson }] : [] });
    }
    if (t.includes('UPDATE findings')) {
      // values[] ends with the id (last bound param in each UPDATE).
      const id = q.values[q.values.length - 1] as string;
      const u: Update = { id, sql: t };
      if (t.includes("status = 'false_positive'")) u.status = 'false_positive';
      // Find the metadata json (a stringified object among the values).
      for (const v of q.values) {
        if (typeof v === 'string' && v.startsWith('{')) { try { u.metadata = JSON.parse(v); } catch { /* */ } }
      }
      if (t.includes('llm_verified = true')) u.llmVerified = true;
      // severity bound param (when severity = $x present)
      if (t.includes('SET severity =')) u.severity = q.values[0] as string;
      updates.push(u);
      return Promise.resolve({ rows: [] });
    }
    return Promise.resolve({ rows: [] });
  });
}

function votes(...v: Array<'true_positive' | 'false_positive' | 'cannot_verify'>): string[] {
  return v.map((x) => `VERDICT: ${x}\nREASON: r`);
}

const baseFinding = (over: Partial<any> = {}) => ({
  id: 'f1', scanner: 'llm-vuln-scan', severity: 'high', status: 'open',
  title: 'SQLi', description: 'sql injection in query', file_path: 'src/db.ts',
  line_number: 10, cwe_id: 'CWE-89', rule_id: 'LLM-VS-sql-injection', metadata: {},
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  agentTexts.length = 0;
  budgetExhausted = false;
  mockEnv.ANTHROPIC_API_KEY = 'test-key';
  mockEnv.LLM_TRIAGE_VOTES = 3;
});

describe('llm-triage gating', () => {
  it('no-ops with zeros when no API key', async () => {
    mockEnv.ANTHROPIC_API_KEY = undefined;
    setupDb([baseFinding()]);
    const r = await runTriageStage('scan-1');
    expect(r).toEqual({ triaged: 0, duplicates: 0, falsePositives: 0, recalibrated: 0 });
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });

  it('no-ops when project not opted in', async () => {
    dbExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
      if (sqlText(q).includes('llm_analysis_enabled AS enabled')) return Promise.resolve({ rows: [{ enabled: false }] });
      return Promise.resolve({ rows: [] });
    });
    const r = await runTriageStage('scan-1');
    expect(r.triaged).toBe(0);
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });
});

describe('llm-triage N-vote verification', () => {
  it('false_positive majority suppresses a non-deterministic finding', async () => {
    setupDb([baseFinding()]);
    agentTexts.push(...votes('false_positive', 'false_positive', 'true_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(1);
    const u = updates.find((x) => x.id === 'f1');
    expect(u?.status).toBe('false_positive');
    expect(u?.metadata.triage.verdict).toBe('false_positive');
  });

  it('true_positive majority marks llm_verified and stays open', async () => {
    setupDb([baseFinding()]);
    agentTexts.push(...votes('true_positive', 'true_positive', 'false_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.triaged).toBe(1);
    expect(r.falsePositives).toBe(0);
    const u = updates.find((x) => x.id === 'f1');
    expect(u?.llmVerified).toBe(true);
    expect(u?.metadata.triage.verdict).toBe('true_positive');
  });

  it('a tie keeps the finding open (no suppression)', async () => {
    setupDb([baseFinding()]);
    agentTexts.push(...votes('true_positive', 'false_positive', 'cannot_verify'));
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(0);
    const u = updates.find((x) => x.id === 'f1');
    expect(u?.status).not.toBe('false_positive');
    expect(u?.metadata.triage.verdict).toBe('cannot_verify');
  });
});

describe('llm-triage R7 deterministic protection', () => {
  it('never auto-suppresses a deterministic critical on false_positive votes — downgrades + disputes', async () => {
    setupDb([baseFinding({ id: 'd1', scanner: 'bandit', severity: 'critical' })]);
    agentTexts.push(...votes('false_positive', 'false_positive', 'false_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(0); // not auto-suppressed
    const u = updates.find((x) => x.id === 'd1');
    expect(u?.status).not.toBe('false_positive');
    expect(u?.severity).toBe('high'); // downgraded one step from critical
    expect(u?.metadata.triage.disputed).toBe(true);
  });

  it('never auto-suppresses a deterministic HIGH on false_positive votes — downgrades to medium + disputes (R7)', async () => {
    // QA G-02: deterministic high through the N-vote path with false_positive majority.
    setupDb([baseFinding({ id: 'h1', scanner: 'gosec', severity: 'high' })]);
    agentTexts.push(...votes('false_positive', 'false_positive', 'false_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.triaged).toBe(1);     // it WAS voted on (deterministic high isn't pre-FP'd off a non-test path)
    expect(r.falsePositives).toBe(0); // not auto-suppressed
    const u = updates.find((x) => x.id === 'h1');
    expect(u?.status).not.toBe('false_positive');
    expect(u?.severity).toBe('medium'); // downgraded one step from high
    expect(u?.metadata.triage.disputed).toBe(true);
  });
});

describe('llm-triage cross-scanner dedupe', () => {
  it('deterministic finding survives the cluster even if shorter (R7)', async () => {
    // llm finding has a longer description but the deterministic one must survive.
    setupDb([
      baseFinding({ id: 'llm1', scanner: 'llm-vuln-scan', severity: 'high', description: 'x'.repeat(200), line_number: 10 }),
      baseFinding({ id: 'det1', scanner: 'semgrep', severity: 'high', description: 'short', line_number: 12 }),
    ]);
    // Survivor gets voted on; make it true_positive so it stays open cleanly.
    agentTexts.push(...votes('true_positive', 'true_positive', 'true_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.duplicates).toBe(1);
    // The llm one is the duplicate (suppressed), det1 survives.
    const dup = updates.find((x) => x.id === 'llm1' && x.status === 'false_positive');
    expect(dup?.metadata.triage.verdict).toBe('duplicate');
    expect(dup?.metadata.triage.duplicateOf).toBe('det1');
  });

  it('longest description survives when no deterministic critical/high present', async () => {
    setupDb([
      baseFinding({ id: 'a', scanner: 'llm-vuln-scan', severity: 'medium', description: 'short', line_number: 10 }),
      baseFinding({ id: 'b', scanner: 'llm-vuln-scan', severity: 'medium', description: 'x'.repeat(100), line_number: 11 }),
    ]);
    agentTexts.push(...votes('cannot_verify', 'cannot_verify', 'cannot_verify'));
    const r = await runTriageStage('scan-1');
    expect(r.duplicates).toBe(1);
    const dup = updates.find((x) => x.status === 'false_positive');
    expect(dup?.id).toBe('a'); // shorter one suppressed
    expect(dup?.metadata.triage.duplicateOf).toBe('b');
  });
});

describe('llm-triage test/fixture FP exclusion', () => {
  it('auto-FPs a finding in a test path (non-deterministic)', async () => {
    setupDb([baseFinding({ id: 't1', file_path: 'src/__tests__/db.test.ts' })]);
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(1);
    const u = updates.find((x) => x.id === 't1');
    expect(u?.status).toBe('false_positive');
    expect(u?.sql).toContain('dismissed_reason');
    // Should not have voted on it (it was excluded before the API stage).
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });

  it('exempts a deterministic critical in a test path — downgrade only', async () => {
    setupDb([baseFinding({ id: 'dc', scanner: 'gosec', severity: 'critical', file_path: 'tests/x_test.go' })]);
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(0);
    const u = updates.find((x) => x.id === 'dc');
    expect(u?.status).not.toBe('false_positive');
    expect(u?.severity).toBe('high');
  });

  it('exempts a deterministic high in a test path — downgrade + dispute, not suppressed', async () => {
    setupDb([baseFinding({ id: 'dh', scanner: 'gosec', severity: 'high', file_path: 'tests/x_test.go' })]);
    const r = await runTriageStage('scan-1');
    expect(r.falsePositives).toBe(0);
    const u = updates.find((x) => x.id === 'dh');
    expect(u?.status).not.toBe('false_positive');
    expect(u?.severity).toBe('medium'); // downgraded one step from high
    expect(u?.metadata.triage.disputed).toBe(true);
  });
});

describe('llm-triage threat-model recalibration', () => {
  const threats = JSON.stringify([
    { id: 'T1', title: 'auth bypass on login', actor: 'remote_unauth', surface: 'login endpoint', asset: 'accounts', impact: 'critical', likelihood: 'likely', status: 'unmitigated', controls: 'none', evidence: '' },
    { id: 'T2', title: 'minor', actor: 'local_user', surface: 'config parser', asset: 'config', impact: 'low', likelihood: 'rare', status: 'mitigated', controls: 'validated', evidence: '' },
  ]);

  it('ranks UP a finding matching an unmitigated critical threat surface', async () => {
    setupDb([baseFinding({ id: 'r1', severity: 'medium', file_path: 'src/login.ts', title: 'weak check', cwe_id: null })], threats);
    agentTexts.push(...votes('true_positive', 'true_positive', 'true_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.recalibrated).toBe(1);
    const u = updates.find((x) => x.id === 'r1' && x.severity);
    expect(u?.severity).toBe('high');
    expect(u?.metadata.triage.recalibrated.from).toBe('medium');
    expect(u?.metadata.triage.recalibrated.to).toBe('high');
  });

  it('ranks DOWN a finding matching only a mitigated threat surface', async () => {
    setupDb([baseFinding({ id: 'r2', severity: 'medium', file_path: 'src/config.ts', title: 'config parser issue', cwe_id: null })], threats);
    agentTexts.push(...votes('true_positive', 'true_positive', 'true_positive'));
    const r = await runTriageStage('scan-1');
    expect(r.recalibrated).toBe(1);
    const u = updates.find((x) => x.id === 'r2' && x.severity);
    expect(u?.severity).toBe('low');
  });
});

describe('llm-triage budget exhaustion', () => {
  it('returns partial counts and stops API voting when budget is exhausted', async () => {
    budgetExhausted = true;
    setupDb([baseFinding({ id: 'b1' }), baseFinding({ id: 'b2', file_path: 'src/other.ts', line_number: 99 })]);
    const r = await runTriageStage('scan-1');
    // No votes happened — triaged stays 0, no throw.
    expect(r.triaged).toBe(0);
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });

  it('a budget exhausted by a PRIOR stage causes zero API calls and zeros (§11 R2 cross-stage)', async () => {
    // Simulate a shared scan-scoped budget already drained by llm-vuln-scan/threatmodel
    // before triage runs. Triage must do no API work and report zeros.
    budgetExhausted = true;
    const sharedBudget = new ScanTokenBudget(500000);
    expect(sharedBudget.exhausted).toBe(true);
    setupDb([baseFinding({ id: 'x1' }), baseFinding({ id: 'x2', file_path: 'src/other.ts', line_number: 99 })]);
    const r = await runTriageStage('scan-1', sharedBudget);
    expect(r.triaged).toBe(0);
    expect(r.falsePositives).toBe(0);
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });
});
