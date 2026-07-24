import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const mockEnv = {
  ANTHROPIC_API_KEY: 'test-key' as string | undefined,
  LLM_SCAN_MODEL: 'claude-sonnet-test',
  LLM_PATCH_MAX_FINDINGS: 5,
  LLM_SCAN_MAX_TOKENS_PER_AREA: 8000,
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

const agentTexts: string[] = [];
const runBoundedAgent = vi.fn(async () => {
  const text = agentTexts.length ? agentTexts.shift()! : '<patch_diff>NONE</patch_diff>';
  return { finalText: text, iterations: 1, stopReason: 'end_turn', inputTokens: 1, outputTokens: 1 };
});
let budgetExhausted = false;
vi.mock('./llm-agent.js', () => ({
  runBoundedAgent: (...a: unknown[]) => runBoundedAgent(...a),
  ScanTokenBudget: class {
    get exhausted() { return budgetExhausted; }
    consume() { return true; }
    remaining() { return 1000; }
  },
}));

import { generateCandidatePatches, parsePatch, unescapeEntities } from './llm-patch.js';

function sqlText(q: { strings: TemplateStringsArray }): string {
  return q.strings.join(' ');
}

interface Insert { findingId: string; patchDiff: string; rationale: string; validationNotes: string }
let inserts: Insert[] = [];

function setupDb(candidates: any[]) {
  inserts = [];
  dbExecute.mockImplementation((q: { strings: TemplateStringsArray; values: unknown[] }) => {
    const t = sqlText(q);
    if (t.includes('llm_analysis_enabled AS enabled')) {
      return Promise.resolve({ rows: [{ enabled: true }] });
    }
    if (t.includes('FROM findings') && t.includes('exploitability IN')) {
      return Promise.resolve({ rows: candidates });
    }
    if (t.includes('INSERT INTO candidate_patches')) {
      inserts.push({
        findingId: q.values[0] as string,
        patchDiff: q.values[2] as string,
        rationale: q.values[3] as string,
        validationNotes: q.values[4] as string,
      });
      return Promise.resolve({ rows: [] });
    }
    return Promise.resolve({ rows: [] });
  });
}

const finding = (over: Partial<any> = {}) => ({
  id: 'f1', scanner: 'llm-vuln-scan', severity: 'high', title: 'SQLi',
  description: 'sql injection', file_path: 'src/db.ts', line_number: 10,
  cwe_id: 'CWE-89', fix_description: null, ...over,
});

const DIFF = `<patch_diff>
--- a/src/db.ts
+++ b/src/db.ts
@@ -8,3 +8,3 @@
-  db.query("SELECT * FROM u WHERE id=" + id)
+  db.query("SELECT * FROM u WHERE id=?", [id])
</patch_diff>
<rationale>Parameterize the query to close the injection class.</rationale>
<validation_notes>builds: yes; exploit path closed: yes; tests: unaffected; bypass: none</validation_notes>`;

beforeEach(() => {
  vi.clearAllMocks();
  agentTexts.length = 0;
  budgetExhausted = false;
  mockEnv.ANTHROPIC_API_KEY = 'test-key';
  mockEnv.LLM_PATCH_MAX_FINDINGS = 5;
});

describe('parsePatch', () => {
  it('parses a diff with rationale and validation notes', () => {
    const p = parsePatch(DIFF);
    expect(p).not.toBeNull();
    expect(p!.patchDiff).toContain('SELECT * FROM u WHERE id=?');
    expect(p!.rationale).toContain('Parameterize');
    expect(p!.validationNotes).toContain('bypass: none');
  });

  it('returns null for <patch_diff>NONE', () => {
    expect(parsePatch('<patch_diff>NONE</patch_diff><rationale>n/a</rationale>')).toBeNull();
  });

  it('unescapes HTML entities in the diff', () => {
    const text = '<patch_diff>if (a &lt; b &amp;&amp; c &gt; d) {}</patch_diff><rationale>r</rationale><validation_notes>v</validation_notes>';
    const p = parsePatch(text);
    expect(p!.patchDiff).toBe('if (a < b && c > d) {}');
  });
});

describe('unescapeEntities', () => {
  it('decodes the supported entity set', () => {
    expect(unescapeEntities('&lt;a&gt; &amp; &quot;x&quot; &#39;y&#39;')).toBe('<a> & "x" \'y\'');
  });
});

describe('generateCandidatePatches', () => {
  it('inserts a row when the LLM returns a diff', async () => {
    setupDb([finding()]);
    agentTexts.push(DIFF);
    const n = await generateCandidatePatches('scan-1');
    expect(n).toBe(1);
    expect(inserts).toHaveLength(1);
    expect(inserts[0].findingId).toBe('f1');
    expect(inserts[0].patchDiff).toContain('id=?');
  });

  it('inserts no row when the LLM returns NONE', async () => {
    setupDb([finding()]);
    agentTexts.push('<patch_diff>NONE</patch_diff><rationale>no safe fix</rationale>');
    const n = await generateCandidatePatches('scan-1');
    expect(n).toBe(0);
    expect(inserts).toHaveLength(0);
  });

  it('caps generation at LLM_PATCH_MAX_FINDINGS', async () => {
    // 5 candidates already returned by the query (LIMIT enforced in SQL); simulate
    // the query returning exactly the cap and assert we patch all of them.
    const five = Array.from({ length: 5 }, (_, i) => finding({ id: `f${i}` }));
    setupDb(five);
    for (let i = 0; i < 5; i++) agentTexts.push(DIFF);
    const n = await generateCandidatePatches('scan-1');
    expect(n).toBe(5);
    expect(mockEnv.LLM_PATCH_MAX_FINDINGS).toBe(5);
    // The candidate query bound the LIMIT param to the cap.
    const limitCall = dbExecute.mock.calls.find(
      (c: any[]) => sqlText(c[0]).includes('FROM findings') && sqlText(c[0]).includes('exploitability IN'),
    );
    expect((limitCall![0] as any).values).toContain(5);
  });

  it('no-ops when not opted in', async () => {
    dbExecute.mockImplementation((q: { strings: TemplateStringsArray }) => {
      if (sqlText(q).includes('llm_analysis_enabled AS enabled')) return Promise.resolve({ rows: [{ enabled: false }] });
      return Promise.resolve({ rows: [] });
    });
    const n = await generateCandidatePatches('scan-1');
    expect(n).toBe(0);
    expect(runBoundedAgent).not.toHaveBeenCalled();
  });
});

describe('llm-patch never writes to disk (R4)', () => {
  it('the module source imports no fs write API', () => {
    const src = readFileSync(path.join(__dirname, 'llm-patch.ts'), 'utf8');
    // No fs import at all, and no write/apply syscalls anywhere in the module.
    expect(src).not.toMatch(/from 'node:fs'/);
    expect(src).not.toMatch(/writeFile|appendFile|writeFileSync|createWriteStream|fs\.write/);
  });
});
