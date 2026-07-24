import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';

// Mutable env so individual tests can toggle the API key.
const mockEnv = {
  ANTHROPIC_API_KEY: 'test-key' as string | undefined,
  LLM_THREATMODEL_MODEL: 'claude-haiku-test',
  LLM_SCAN_MAX_TOTAL_TOKENS: 2000000,
  LLM_THREATMODEL_MAX_TOKENS: 150000,
  LLM_THREATMODEL_MAX_ITERATIONS: 14,
  LOG_LEVEL: 'silent',
  NODE_ENV: 'test',
};

vi.mock('../../config/env.js', () => ({
  get env() { return mockEnv; },
  get llmVerifyEnabled() { return !!mockEnv.ANTHROPIC_API_KEY; },
  isDev: false,
}));

vi.mock('../../utils/logger.js', () => ({
  createLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

// db client mock — db.execute resolves a queue of { rows } results.
const dbExecute = vi.fn();
// F6: the regenerate path acquires a pooled client and runs the advisory-lock
// transaction (BEGIN / pg_advisory_xact_lock / re-check SELECT / INSERT / COMMIT)
// via client.query. `poolQuery` records those calls so tests can assert them.
const poolQuery = vi.fn().mockResolvedValue({ rows: [] });
const poolClient = { query: (...a: unknown[]) => poolQuery(...a), release: vi.fn() };
const poolConnect = vi.fn(async () => poolClient);
vi.mock('../../db/client.js', () => ({
  db: { execute: (...a: unknown[]) => dbExecute(...a) },
  pool: { connect: (...a: unknown[]) => poolConnect(...a) },
}));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));

// Code analysis returns null in tests (the scanner tolerates that).
vi.mock('./code-analysis.js', () => ({ runCodeAnalysis: vi.fn().mockResolvedValue(null) }));

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { runLlmThreatmodel, parseThreatsSection } from './llm-threatmodel.js';
import type { ScanJobData } from '../queue/scan.queue.js';

function jobData(): ScanJobData {
  return {
    scanId: 'scan-1', projectId: 'proj-1', userId: 'user-1',
    profile: 'deep', branch: 'main', scanners: [],
  };
}

/** Make the agent loop terminate in one turn with the given text. */
function apiText(text: string) {
  return {
    ok: true, status: 200,
    json: async () => ({ content: [{ type: 'text', text }], stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 5 } }),
  };
}

/**
 * A `tool_use` turn that emits some interim narration text AND requests a tool,
 * reporting `usage` token counts. Used to drive the agent loop multiple turns
 * and (with large usage) to drain the stage budget mid-generation so the NEXT
 * loop iteration returns stopReason 'budget_exhausted' — the live-defect shape.
 */
function apiToolUse(text: string, usageTokens: number) {
  return {
    ok: true, status: 200,
    json: async () => ({
      content: [
        { type: 'text', text },
        { type: 'tool_use', id: 'tu-1', name: 'list_files', input: {} },
      ],
      stop_reason: 'tool_use',
      usage: { input_tokens: usageTokens, output_tokens: 0 },
    }),
  };
}

const realScanTarget = '/scan-target';
// The scanner walks /scan-target via fs; we cannot create that path, so we stub
// fs.readdir/stat/realpath used by collectInventory + the agent realpath.
let fsSpies: Array<{ mockRestore: () => void }> = [];

function stubScanTargetFs() {
  // Empty inventory is fine — hash is deterministic over zero entries.
  fsSpies.push(vi.spyOn(fs, 'readdir').mockResolvedValue([] as never));
  fsSpies.push(vi.spyOn(fs, 'realpath').mockResolvedValue(realScanTarget as never));
}

const SAMPLE_TM = `# Threat Model: Demo

## 1. System context
A demo service.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| data | user data | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| http api | REST endpoints | unauth network → app | data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | RCE via upload parsing | remote_unauth | http api | data | critical | likely | unmitigated | none | CVE-2024-1 |
| T2 | Info leak in logs | remote_auth | http api | data | low | possible | mitigated | redaction | |

## 5. Deprioritized

| threat | reason |
|---|---|

## 6. Open questions

- none

## 7. Provenance
- mode: bootstrap

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
`;

beforeEach(() => {
  mockEnv.ANTHROPIC_API_KEY = 'test-key';
  dbExecute.mockReset();
  mockFetch.mockReset();
  poolQuery.mockReset();
  poolQuery.mockResolvedValue({ rows: [] }); // default: re-check finds nothing fresh
  poolConnect.mockReset();
  poolConnect.mockImplementation(async () => poolClient);
  poolClient.release.mockReset();
  fsSpies = [];
});

afterEach(() => {
  for (const s of fsSpies) s.mockRestore();
  vi.restoreAllMocks();
});

describe('parseThreatsSection (§11 B2)', () => {
  it('parses a valid section-4 table into ParsedThreat[]', () => {
    const threats = parseThreatsSection(SAMPLE_TM);
    expect(threats).toHaveLength(2);
    expect(threats[0]).toMatchObject({
      id: 'T1', actor: 'remote_unauth', impact: 'critical', likelihood: 'likely', status: 'unmitigated',
    });
    expect(threats[0].title).toContain('RCE');
  });

  it('drops rows with off-allowlist enum values', () => {
    const bad = SAMPLE_TM.replace('remote_unauth', 'space_alien').replace('critical', 'apocalyptic');
    const threats = parseThreatsSection(bad);
    // T1 row dropped (bad actor+impact); T2 remains.
    expect(threats.map((t) => t.id)).toEqual(['T2']);
  });

  it('returns [] when section 4 is missing/malformed', () => {
    expect(parseThreatsSection('# no sections here')).toEqual([]);
  });

  it('parses a row with an escaped pipe in the description into the right columns (F10)', () => {
    // The threat cell contains a literal pipe written as `\|`; it must NOT split
    // the row into extra columns — the description stays one cell, and the enum
    // columns after it still line up.
    const tm = `# Threat Model: Demo

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | bypass A \\| B check | remote_unauth | gw | data | high | likely | unmitigated | none | |

## 5. Deprioritized
`;
    const threats = parseThreatsSection(tm);
    expect(threats).toHaveLength(1);
    // The escaped pipe is unescaped back to a literal `|` and kept in one cell.
    expect(threats[0].title).toBe('bypass A | B check');
    // The columns AFTER the escaped-pipe cell still align correctly.
    expect(threats[0]).toMatchObject({
      id: 'T1', actor: 'remote_unauth', surface: 'gw',
      impact: 'high', likelihood: 'likely', status: 'unmitigated',
    });
  });
});

describe('runLlmThreatmodel — gating', () => {
  it('skips without an API key', async () => {
    mockEnv.ANTHROPIC_API_KEY = undefined;
    const r = await runLlmThreatmodel(jobData());
    expect(r.skipped).toBe(true);
    expect(r.skipReason).toBe('no_llm_api_key');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('skips when the project has not opted in', async () => {
    dbExecute.mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: false }] });
    const r = await runLlmThreatmodel(jobData());
    expect(r.skipped).toBe(true);
    expect(r.skipReason).toBe('llm_not_opted_in');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('runLlmThreatmodel — staleness reuse', () => {
  it('reuses a stored model on hash match with ZERO API calls and re-emits findings', async () => {
    stubScanTargetFs();
    const storedThreats = parseThreatsSection(SAMPLE_TM);
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] }) // opt-in
      .mockImplementationOnce(async () => {
        // The stored hash must equal the freshly computed (empty-inventory) hash.
        const { createHash } = await import('node:crypto');
        const hash = createHash('sha256').digest('hex');
        return { rows: [{ content: SAMPLE_TM, threats_json: JSON.stringify(storedThreats), source_inventory_hash: hash, model_used: 'cached-model' }] };
      });

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    expect(mockFetch).not.toHaveBeenCalled();
    // info findings only for unmitigated critical/high/existential → just T1.
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].ruleId).toBe('LLM-TM-T1');
    expect(r.findings[0].severity).toBe('info');
  });
});

describe('runLlmThreatmodel — regenerate path', () => {
  it('calls the API and upserts under the advisory lock when the hash mismatches', async () => {
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })       // opt-in
      .mockResolvedValueOnce({ rows: [{ content: 'old', threats_json: '[]', source_inventory_hash: 'STALE', model_used: 'm' }] }); // stored (mismatch)
    // F6: re-check under the lock also finds STALE (different hash) → regenerate.
    // poolQuery default returns { rows: [] } for every client.query (BEGIN, lock,
    // re-check SELECT, INSERT, COMMIT).
    mockFetch.mockResolvedValueOnce(apiText(SAMPLE_TM));

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    // The transactional INSERT (upsert) ran on the locked client.
    const insertCall = poolQuery.mock.calls.find((c) => String(c[0]).includes('INSERT INTO threat_models'));
    expect(insertCall).toBeDefined();
    // BEGIN, advisory lock, and COMMIT were issued.
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('BEGIN'))).toBe(true);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('pg_advisory_xact_lock'))).toBe(true);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('COMMIT'))).toBe(true);
    expect(poolClient.release).toHaveBeenCalledTimes(1);
    // info finding emitted for unmitigated critical threat.
    expect(r.findings.map((f) => f.ruleId)).toContain('LLM-TM-T1');
  });

  it('stores markdown with empty threats_json when a STRUCTURALLY-COMPLETE model has no threat rows', async () => {
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })
      .mockResolvedValueOnce({ rows: [] });   // no stored model
    // A complete 8-section document (passes the FIX A validity gate: clean
    // end_turn, has `## 1.`/`## 4.`, > 500 chars) whose section-4 table has the
    // header + separator but ZERO data rows → parses to []. This is the
    // legitimate "valid model, no threats" path; it must still persist.
    const EMPTY_THREATS_TM = SAMPLE_TM
      .replace('| T1 | RCE via upload parsing | remote_unauth | http api | data | critical | likely | unmitigated | none | CVE-2024-1 |\n', '')
      .replace('| T2 | Info leak in logs | remote_auth | http api | data | low | possible | mitigated | redaction | |\n', '');
    mockFetch.mockResolvedValueOnce(apiText(EMPTY_THREATS_TM));

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    expect(r.findings).toHaveLength(0);
    // upsert ran with threats_json '[]' (3rd positional client.query param).
    const insertCall = poolQuery.mock.calls.find((c) => String(c[0]).includes('INSERT INTO threat_models'));
    expect(insertCall).toBeDefined();
    expect((insertCall as unknown[])[1]).toMatchObject({ 2: '[]' }); // params[2] = threatsJson
  });

  it('does NOT persist and skips with llm_budget_exhausted when the agent exhausts its budget mid-generation (FIX A)', async () => {
    // Live-defect shape: the bounded agent drains its budget DURING exploration
    // and its last finalText is a mid-investigation narration line, not a full
    // THREAT_MODEL.md. The scanner must persist NOTHING (no cache poison) and
    // skip with llm_budget_exhausted.
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] }) // opt-in
      .mockResolvedValueOnce({ rows: [] });                              // no stored model
    // First (and only) API turn: tool_use with narration text + usage that
    // exceeds the stage cap (LLM_THREATMODEL_MAX_TOKENS=150000), draining the
    // ScopedTokenBudget. After the tool_result is appended, runBoundedAgent's
    // bottom-of-loop budget check returns stopReason 'budget_exhausted' with the
    // narration as finalText.
    mockFetch.mockResolvedValueOnce(
      apiToolUse('Now let me check for input validation vulnerabilities...', 200000),
    );

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    expect(r.skipped).toBe(true);
    expect(r.skipReason).toBe('llm_budget_exhausted');
    expect(r.findings).toHaveLength(0);
    // CORE ASSERTION: no row was written — the staleness cache is not poisoned.
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('INSERT INTO threat_models'))).toBe(false);
    // The advisory-lock transaction was rolled back, not committed.
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('ROLLBACK'))).toBe(true);
    expect(poolClient.release).toHaveBeenCalledTimes(1);
  });

  it('does NOT persist and skips with llm_threatmodel_incomplete on a clean end_turn that lacks section 4 / is too short (FIX A)', async () => {
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] }) // opt-in
      .mockResolvedValueOnce({ rows: [] });                              // no stored model
    // Clean end_turn, but the content is a short narration line with no `## 4.
    // Threats` heading — structurally invalid, must not be stored.
    mockFetch.mockResolvedValueOnce(apiText('Now let me check for input validation vulnerabilities...'));

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    expect(r.skipped).toBe(true);
    expect(r.skipReason).toBe('llm_threatmodel_incomplete');
    expect(r.findings).toHaveLength(0);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('INSERT INTO threat_models'))).toBe(false);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('ROLLBACK'))).toBe(true);
  });

  it('caps the threat-model agent at LLM_THREATMODEL_MAX_TOKENS without draining the shared budget (FIX B)', async () => {
    // The stage cap (here 150000) bounds this stage independently of the much
    // larger shared budget. One tool_use turn reporting 200000 tokens exhausts
    // the ScopedTokenBudget (stage) and stops generation — proving the stage was
    // capped at LLM_THREATMODEL_MAX_TOKENS, not at the 2M shared aggregate.
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })
      .mockResolvedValueOnce({ rows: [] });
    const { ScanTokenBudget } = await import('./llm-agent.js');
    const sharedBudget = new ScanTokenBudget(mockEnv.LLM_SCAN_MAX_TOTAL_TOKENS);
    const job = { ...jobData(), llmBudget: sharedBudget };
    // 200000 > stage cap 150000 but << shared 2,000,000.
    mockFetch.mockResolvedValueOnce(apiToolUse('exploring...', 200000));

    const r = await runLlmThreatmodel(job);
    // Stage hit its reservation and stopped (budget_exhausted), so the scanner
    // skips — exactly ONE API turn ran before the stage cap tripped.
    expect(r.skipReason).toBe('llm_budget_exhausted');
    expect(mockFetch).toHaveBeenCalledTimes(1);
    // The shared budget was debited by the stage's usage (R2: aggregate counts
    // this stage), but is NOT exhausted — vuln-scan still has headroom.
    expect(sharedBudget.remaining()).toBe(2000000 - 200000);
    expect(sharedBudget.exhausted).toBe(false);
  });

  it('reuses a peer-generated model when the re-check under the lock finds it fresh (F6)', async () => {
    stubScanTargetFs();
    // The stubbed inventory is empty, so the scanner computes a deterministic
    // sha256 of zero entries (= sha256 of empty input).
    const EMPTY_TREE_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })       // opt-in
      .mockResolvedValueOnce({ rows: [] });                                     // no stored model (first check, pre-lock)
    // Under the advisory lock, the re-check SELECT returns a model whose hash
    // MATCHES — a peer generated it while we waited for the lock.
    const peerThreatsJson = JSON.stringify(parseThreatsSection(SAMPLE_TM));
    poolQuery.mockImplementation(async (text: string) => {
      if (String(text).includes('SELECT') && String(text).includes('threat_models')) {
        return { rows: [{ content: SAMPLE_TM, threats_json: peerThreatsJson, source_inventory_hash: EMPTY_TREE_HASH, model_used: 'peer' }] };
      }
      return { rows: [] };
    });

    const r = await runLlmThreatmodel(jobData());
    expect(r.success).toBe(true);
    // No API call: the re-check served the peer's fresh model with zero tokens.
    expect(mockFetch).not.toHaveBeenCalled();
    // No INSERT: nothing was regenerated; the transaction committed the no-op.
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('INSERT INTO threat_models'))).toBe(false);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('COMMIT'))).toBe(true);
    expect(poolClient.release).toHaveBeenCalledTimes(1);
    // The cached model's findings still surface (LLM-TM-T1 from SAMPLE_TM).
    expect(r.findings.map((f) => f.ruleId)).toContain('LLM-TM-T1');
  });

  it('bounds the threat-model agent at LLM_THREATMODEL_MAX_ITERATIONS (convergence pressure, FIX C)', async () => {
    // Convergence guard: the scanner must pass maxIterations = LLM_THREATMODEL_MAX_ITERATIONS
    // (14) to runBoundedAgent, NOT the default 25. Drive the real agent loop with a
    // response that ALWAYS requests a tool with negligible token usage so neither the
    // stage cap nor the shared budget ever trips — the ONLY thing that can stop the
    // loop is the iteration cap. The number of API turns then equals the cap, proving
    // it was bounded at 14 (a default of 25 would yield 25 turns).
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] }) // opt-in
      .mockResolvedValueOnce({ rows: [] });                              // no stored model
    // Every turn is a tool_use with ~1 token of usage → loop never budget-stops.
    mockFetch.mockResolvedValue(apiToolUse('still exploring…', 1));

    const r = await runLlmThreatmodel(jobData());
    // The loop hit max_iterations without a complete document → not persisted.
    expect(r.skipped).toBe(true);
    expect(poolQuery.mock.calls.some((c) => String(c[0]).includes('INSERT INTO threat_models'))).toBe(false);
    // CORE ASSERTION: exactly LLM_THREATMODEL_MAX_ITERATIONS API turns ran, and it
    // is bounded at/below 14 — proving the lower iteration cap was wired through.
    expect(mockFetch).toHaveBeenCalledTimes(mockEnv.LLM_THREATMODEL_MAX_ITERATIONS);
    expect(mockFetch.mock.calls.length).toBeLessThanOrEqual(14);
  });
});
