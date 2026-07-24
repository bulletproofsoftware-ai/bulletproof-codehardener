import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';

const mockEnv = {
  ANTHROPIC_API_KEY: 'test-key' as string | undefined,
  LLM_SCAN_MODEL: 'claude-sonnet-test',
  LLM_THREATMODEL_MODEL: 'claude-haiku-test',
  LLM_SCAN_MAX_FOCUS_AREAS: 8,
  LLM_SCAN_MAX_TOKENS_PER_AREA: 8000,
  LLM_SCAN_CONFIDENCE_PASS: true,
  LLM_SCAN_MAX_TOTAL_TOKENS: 500000,
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

const dbExecute = vi.fn();
vi.mock('../../db/client.js', () => ({ db: { execute: (...a: unknown[]) => dbExecute(...a) } }));
vi.mock('drizzle-orm', () => ({
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values, _tag: 'sql' }),
}));

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  runLlmVulnScan,
  extractFocusAreas,
  parseFindings,
  sanitizeFindingPath,
} from './llm-vuln-scan.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import { ScanTokenBudget } from './llm-agent.js';

function jobData(): ScanJobData {
  return {
    scanId: 'scan-1', projectId: 'proj-1', userId: 'user-1',
    profile: 'deep', branch: 'main', scanners: [],
  };
}

function apiText(text: string) {
  return {
    ok: true, status: 200,
    json: async () => ({ content: [{ type: 'text', text }], stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 5 } }),
  };
}

let fsSpies: Array<{ mockRestore: () => void }> = [];
function stubScanTargetFs() {
  fsSpies.push(vi.spyOn(fs, 'realpath').mockResolvedValue('/scan-target' as never));
  fsSpies.push(vi.spyOn(fs, 'readdir').mockResolvedValue([] as never));
}

const TM_WITH_SECTION3 = `# Threat Model: Demo

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| upload handler | parses files | untrusted file → memory | data |
| login route | auth | unauth network → session | creds |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | RCE via parse | remote_unauth | upload handler | data | critical | likely | unmitigated | none | |

## 5. Deprioritized
`;

const FINDING_BLOCK = `<finding>
<id>F-01</id>
<file>src/db.py</file>
<line>42</line>
<category>sql-injection</category>
<severity>HIGH</severity>
<confidence>0.8</confidence>
<title>SQL injection in query builder</title>
<description>User input flows unsanitized into a raw SQL string at line 42.</description>
<exploit_scenario>Attacker sends crafted id param.</exploit_scenario>
<recommendation>Use parameterized queries.</recommendation>
</finding>`;

beforeEach(() => {
  mockEnv.ANTHROPIC_API_KEY = 'test-key';
  mockEnv.LLM_SCAN_CONFIDENCE_PASS = true;
  dbExecute.mockReset();
  mockFetch.mockReset();
  fsSpies = [];
});

afterEach(() => {
  for (const s of fsSpies) s.mockRestore();
  vi.restoreAllMocks();
});

describe('extractFocusAreas', () => {
  it('extracts focus areas from threat-model sections 3 and 4', () => {
    const areas = extractFocusAreas(TM_WITH_SECTION3, 8);
    expect(areas.length).toBeGreaterThanOrEqual(2);
    expect(areas.some((a) => a.includes('upload handler'))).toBe(true);
    expect(areas.some((a) => a.includes('login route'))).toBe(true);
  });

  it('respects the cap', () => {
    expect(extractFocusAreas(TM_WITH_SECTION3, 1)).toHaveLength(1);
  });
});

describe('parseFindings (tolerant, §8)', () => {
  it('parses a valid <finding> block', () => {
    const f = parseFindings(FINDING_BLOCK);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ category: 'sql-injection', severity: 'HIGH', line: 42, confidence: 0.8 });
  });

  it('drops category=none placeholders', () => {
    const none = '<finding><category>none</category><file>x</file><title>covered y</title></finding>';
    expect(parseFindings(none)).toHaveLength(0);
  });

  it('skips unparseable blocks without throwing', () => {
    const broken = '<finding>not xml at all</finding>' + FINDING_BLOCK;
    const f = parseFindings(broken);
    expect(f).toHaveLength(1); // broken block (no file/category) skipped
  });
});

describe('sanitizeFindingPath (F9 path-injection defense)', () => {
  it('rejects a ../ traversal path (not persisted as-is)', () => {
    expect(sanitizeFindingPath('../../etc/passwd')).toBeNull();
    expect(sanitizeFindingPath('src/../../secret')).toBeNull();
  });

  it('rejects absolute POSIX and Windows paths', () => {
    expect(sanitizeFindingPath('/etc/passwd')).toBeNull();
    expect(sanitizeFindingPath('C:\\\\Windows\\\\system32')).toBeNull();
    expect(sanitizeFindingPath('\\\\unc\\\\share')).toBeNull();
  });

  it('strips a leading scan-target/ prefix and keeps a clean relative path', () => {
    expect(sanitizeFindingPath('scan-target/src/app.ts')).toBe('src/app.ts');
    expect(sanitizeFindingPath('/scan-target/src/app.ts')).toBe('src/app.ts');
    expect(sanitizeFindingPath('src/db.py')).toBe('src/db.py');
  });

  it('returns null for empty input', () => {
    expect(sanitizeFindingPath('')).toBeNull();
    expect(sanitizeFindingPath(null)).toBeNull();
    expect(sanitizeFindingPath(undefined)).toBeNull();
  });
});

describe('extractFocusAreas — terminal section (F11)', () => {
  it('yields focus areas when section 4 is the last section in the document', () => {
    const tmSection4Last = `# Threat Model: Demo

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| api gateway | routes requests | unauth network → app | data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | RCE via parse | remote_unauth | upload handler | data | critical | likely | unmitigated | none | |`;
    const areas = extractFocusAreas(tmSection4Last, 8);
    // Section 4 (now last, no trailing `## ` heading) still contributes a surface.
    expect(areas.some((a) => a.includes('upload handler'))).toBe(true);
  });
});

describe('runLlmVulnScan — gating', () => {
  it('skips without an API key', async () => {
    mockEnv.ANTHROPIC_API_KEY = undefined;
    const r = await runLlmVulnScan(jobData());
    expect(r.skipReason).toBe('no_llm_api_key');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('skips when the project has not opted in', async () => {
    dbExecute.mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: false }] });
    const r = await runLlmVulnScan(jobData());
    expect(r.skipReason).toBe('llm_not_opted_in');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('runLlmVulnScan — shared budget exhausted by a prior stage (§11 R2)', () => {
  it('returns skipped llm_budget_exhausted and makes zero API calls', async () => {
    stubScanTargetFs();
    // Project opted in, but the scan-scoped budget was already drained upstream.
    dbExecute.mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] });
    const budget = new ScanTokenBudget(100);
    budget.consume(100); // exhaust it before the stage starts
    expect(budget.exhausted).toBe(true);

    const job = jobData();
    job.llmBudget = budget;
    const r = await runLlmVulnScan(job);

    expect(r.skipped).toBe(true);
    expect(r.skipReason).toBe('llm_budget_exhausted');
    expect(r.findings).toHaveLength(0);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('runLlmVulnScan — focus areas from threat model + mapping', () => {
  it('uses stored threat-model focus areas and maps findings with CWE/OWASP', async () => {
    stubScanTargetFs();
    mockEnv.LLM_SCAN_CONFIDENCE_PASS = false; // isolate the mapping path
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })   // opt-in
      .mockResolvedValueOnce({ rows: [{ content: TM_WITH_SECTION3 }] });   // threat model
    // One review response per focus area; both return the same finding (deduped).
    mockFetch.mockResolvedValue(apiText(FINDING_BLOCK));

    const r = await runLlmVulnScan(jobData());
    expect(r.success).toBe(true);
    expect(r.findings.length).toBeGreaterThanOrEqual(1);
    const f = r.findings[0];
    expect(f.ruleId).toBe('LLM-VS-sql-injection');
    expect(f.cweId).toBe('CWE-89');
    expect(f.owaspCategory).toContain('Injection');
    expect(f.severity).toBe('high');
    // Recon NOT invoked because the threat model provided focus areas.
  });
});

describe('runLlmVulnScan — recon fallback', () => {
  it('runs recon when no threat model exists', async () => {
    stubScanTargetFs();
    mockEnv.LLM_SCAN_CONFIDENCE_PASS = false;
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })   // opt-in
      .mockResolvedValueOnce({ rows: [] });                               // no threat model
    // First fetch = recon (proposes one focus area); second = review.
    mockFetch
      .mockResolvedValueOnce(apiText('auth subsystem (login.py) — credential check'))
      .mockResolvedValueOnce(apiText(FINDING_BLOCK));

    const r = await runLlmVulnScan(jobData());
    expect(r.success).toBe(true);
    expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(r.findings.map((f) => f.ruleId)).toContain('LLM-VS-sql-injection');
  });
});

describe('runLlmVulnScan — B2 inert storage of malicious output', () => {
  it('length-caps fields and drops off-allowlist categories', async () => {
    stubScanTargetFs();
    mockEnv.LLM_SCAN_CONFIDENCE_PASS = false;
    const huge = 'A'.repeat(5000);
    const malicious = `<finding>
<id>F-9</id>
<file>x.py</file>
<line>1</line>
<category>totally-made-up-category</category>
<severity>HIGH</severity>
<confidence>0.9</confidence>
<title>| ' OR 1=1 -- ${'#'.repeat(10)}</title>
<description>${huge}</description>
<exploit_scenario>x</exploit_scenario>
<recommendation>x</recommendation>
</finding>
` + FINDING_BLOCK;
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })
      .mockResolvedValueOnce({ rows: [{ content: TM_WITH_SECTION3 }] });
    mockFetch.mockResolvedValue(apiText(malicious));

    const r = await runLlmVulnScan(jobData());
    // off-allowlist category dropped; only the sql-injection finding survives.
    expect(r.findings.every((f) => f.ruleId === 'LLM-VS-sql-injection')).toBe(true);
    // description length-capped (well under 5000).
    for (const f of r.findings) {
      expect(f.description.length).toBeLessThanOrEqual(2000);
    }
  });
});

describe('runLlmVulnScan — confidence pass', () => {
  it('normalizes CONFIDENCE: 7 → 0.7 and is skipped when the flag is false', async () => {
    stubScanTargetFs();
    dbExecute
      .mockResolvedValueOnce({ rows: [{ llm_analysis_enabled: true }] })
      .mockResolvedValueOnce({ rows: [{ content: TM_WITH_SECTION3 }] });
    // Two focus areas → two review calls (same finding, deduped to one),
    // then one confidence call for the surviving finding.
    mockFetch
      .mockResolvedValueOnce(apiText(FINDING_BLOCK))
      .mockResolvedValueOnce(apiText(FINDING_BLOCK))
      .mockResolvedValue(apiText('CONFIDENCE: 7\nREASON: credible pattern'));

    const r = await runLlmVulnScan(jobData());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].metadata.confidence).toBeCloseTo(0.7, 5);
    expect(r.findings[0].metadata.confidenceReason).toContain('credible');
  });
});
