/**
 * llm-threatmodel scanner — persistent per-project threat model generation.
 *
 * Provenance: ports the harness "bootstrap mode" (threat-model/bootstrap.md +
 * schema.md) from
 *   https://github.com/anthropics/defending-code-reference-harness
 *   https://claude.com/blog/using-llms-to-secure-source-code
 * Prompts are adapted, not copied wholesale: Code Hardener seeds the bootstrap
 * with its own CA-001..010 code-analysis output and persists THREAT_MODEL.md in
 * the database (never in /scan-target, which would self-invalidate the staleness
 * hash — spec §12).
 *
 * Security model (spec §11, BINDING):
 *  - R3: gated by llmVerifyEnabled AND projects.llm_analysis_enabled; otherwise
 *        skipped with a structured skipReason/skipHint.
 *  - B2: every enum field parsed from the section-4 table is validated against a
 *        schema allowlist with length caps; off-list rows are dropped, not stored.
 *        All DB access is parameterized `sql` — never sql.raw() on LLM output.
 *  - R2: a scan-scoped ScanTokenBudget bounds aggregate LLM cost.
 *  - §8/§12: API/parse errors return success:false with an error message; the
 *    scanner never throws out of runLlmThreatmodel.
 */

import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { db, pool } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import { env, llmVerifyEnabled } from '../../config/env.js';
import { runBoundedAgent, ScanTokenBudget, ScopedTokenBudget, type AgentResult } from './llm-agent.js';
import { runCodeAnalysis, type FullAnalysisResult } from './code-analysis.js';
import type { ScanJobData } from '../queue/scan.queue.js';
import type {
  ScannerResult,
  NormalizedFinding,
  ParsedThreat,
} from '../../types/index.js';

const logger = createLogger('llm-threatmodel');

const SCAN_TARGET = '/scan-target';

/** Directories excluded from the inventory hash — mirrors the pipeline's SKIP_DIRS. */
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', '__pycache__',
  '.next', 'dist', 'build', '.cache', '.tox', 'vendor',
  'coverage', '.nyc_output', '.pytest_cache',
]);

/** Max files folded into the inventory hash (defensive bound on huge trees). */
const MAX_INVENTORY_FILES = 20000;

/** §11 B2: per-cell length cap on parsed table values. */
const MAX_CELL_CHARS = 500;

/**
 * Minimum length a THREAT_MODEL.md must reach to be plausibly a full 8-section
 * document. A bounded agent that exhausts its budget/iterations mid-exploration
 * persists its last assistant text (an intermediate narration line, ~96 chars),
 * which is far below this floor — that garbage must never be stored or cached.
 */
const MIN_THREATMODEL_CHARS = 500;

/** §1 heading — verbatim from THREATMODEL_SYSTEM_PROMPT. */
const SECTION_1_HEADING_RE = /^##\s*1\.\s*System context\s*$/m;
/**
 * §4 heading — same shape parseThreatsSection uses to locate the threats table.
 * If this heading is absent the document is structurally incomplete (the agent
 * never reached the threats table), so there is nothing meaningful to persist.
 */
const SECTION_4_HEADING_RE = /^##\s*4\.\s*Threats\s*$/m;

/**
 * FIX A — validity gate for generated threat-model content (the core live-defect
 * fix). Content is a VALID threat model ONLY when the agent finished cleanly
 * (`stopReason === 'end_turn'`) AND the document looks structurally complete:
 * it is at least {@link MIN_THREATMODEL_CHARS} long, opens with the `## 1. System
 * context` heading, and reaches the `## 4. Threats` heading the parser keys off.
 *
 * A budget/token/iteration-exhausted stop, or a too-short / section-4-missing
 * body, is INVALID — those are the cases where the agent persisted mid-
 * investigation narration as if it were a threat model and poisoned the
 * staleness cache.
 */
export function isValidThreatModel(content: string, stopReason: AgentResult['stopReason']): boolean {
  if (stopReason !== 'end_turn') return false;
  const trimmed = content.trim();
  if (trimmed.length < MIN_THREATMODEL_CHARS) return false;
  if (!SECTION_1_HEADING_RE.test(trimmed)) return false;
  if (!SECTION_4_HEADING_RE.test(trimmed)) return false;
  return true;
}

/** stopReasons that mean the agent ran out of budget/tokens/iterations. */
const EXHAUSTION_STOP_REASONS = new Set<AgentResult['stopReason']>([
  'budget_exhausted', 'max_tokens', 'max_iterations',
]);

// ─── §11 B2 enum allowlists (off-list rows dropped, not stored) ───────────────

const ACTOR_ALLOWLIST = new Set([
  'remote_unauth', 'remote_auth', 'adjacent_network',
  'local_user', 'local_admin', 'supply_chain', 'insider',
]);
const IMPACT_ALLOWLIST = new Set<ParsedThreat['impact']>([
  'low', 'medium', 'high', 'critical', 'existential',
]);
const LIKELIHOOD_ALLOWLIST = new Set<ParsedThreat['likelihood']>([
  'very_rare', 'rare', 'possible', 'likely', 'almost_certain',
]);
const STATUS_ALLOWLIST = new Set<ParsedThreat['status']>([
  'unmitigated', 'partially_mitigated', 'mitigated', 'risk_accepted',
]);

// ─── Inventory hash (§11 recommended: include mtime, not just path+size) ──────

interface InventoryEntry {
  rel: string;
  size: number;
  mtimeMs: number;
}

async function collectInventory(root: string): Promise<InventoryEntry[]> {
  const out: InventoryEntry[] = [];
  async function walk(dir: string): Promise<void> {
    if (out.length >= MAX_INVENTORY_FILES) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_INVENTORY_FILES) return;
      if (entry.isSymbolicLink()) continue; // never follow symlinks
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(full);
      } else if (entry.isFile()) {
        try {
          const st = await fs.stat(full);
          out.push({ rel: path.relative(root, full), size: st.size, mtimeMs: Math.floor(st.mtimeMs) });
        } catch {
          // skip unreadable file
        }
      }
    }
  }
  await walk(root);
  return out;
}

/** Deterministic sha256 over sorted relative paths + sizes + mtimes (§11). */
async function computeInventoryHash(root: string): Promise<string> {
  const entries = await collectInventory(root);
  entries.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  const h = createHash('sha256');
  for (const e of entries) {
    h.update(`${e.rel}\0${e.size}\0${e.mtimeMs}\n`);
  }
  return h.digest('hex');
}

// ─── Section-4 markdown table parser (§11 B2 allowlist + length caps) ─────────

function cap(s: string): string {
  const t = s.trim();
  return t.length > MAX_CELL_CHARS ? t.slice(0, MAX_CELL_CHARS) : t;
}

/**
 * F10: split a markdown table row into cells on UNescaped pipes only, then
 * unescape any `\|` back to a literal `|` inside each cell. A value containing an
 * escaped pipe (e.g. `a \| b` in a description) stays in one cell instead of
 * being mis-split into two columns.
 */
function splitTableRow(row: string): string[] {
  // Lookbehind: a `|` preceded by an odd number of backslashes is escaped.
  // `(?<!\\)\|` is sufficient here because the LLM emits at most a single
  // backslash-escape (`\|`); literal backslashes in cells are rare and the
  // unescape pass below only collapses the `\|` sequence.
  return row
    .split(/(?<!\\)\|/)
    .map((c) => c.replace(/\\\|/g, '|').trim());
}

/**
 * Parse the `## 4. Threats` markdown table from THREAT_MODEL.md into ParsedThreat[].
 * Column order is the harness contract: id|threat|actor|surface|asset|impact|
 * likelihood|status|controls|evidence. Off-allowlist enum rows are dropped.
 */
export function parseThreatsSection(markdown: string): ParsedThreat[] {
  // Isolate section 4: from `## 4. Threats` until the next `## ` heading.
  const sectionMatch = markdown.match(/^##\s*4\.\s*Threats\s*$([\s\S]*?)(?=^##\s|$(?![\s\S]))/m);
  if (!sectionMatch) return [];
  const body = sectionMatch[1];

  const threats: ParsedThreat[] = [];
  const lines = body.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('|')) continue;
    // F10: split on UNescaped pipes and unescape `\|` within cells, drop the
    // leading/trailing empty cells. A markdown row like `| a | b |` splits to
    // ['', 'a', 'b', ''].
    const cells = splitTableRow(trimmed);
    const cols = cells.slice(1, cells.length - 1);
    if (cols.length < 10) continue;
    const [id, threat, actor, surface, asset, impact, likelihood, status] = cols;

    // Skip the header row and the separator row.
    if (/^id$/i.test(id) || /^-+$/.test(id.replace(/\s/g, ''))) continue;
    if (cols.every((c) => /^:?-+:?$/.test(c) || c === '')) continue;

    const actorV = actor.toLowerCase();
    const impactV = impact.toLowerCase() as ParsedThreat['impact'];
    const likelihoodV = likelihood.toLowerCase() as ParsedThreat['likelihood'];
    const statusV = status.toLowerCase() as ParsedThreat['status'];

    // §11 B2: validate enums against allowlists; drop off-list rows.
    if (!ACTOR_ALLOWLIST.has(actorV) ||
        !IMPACT_ALLOWLIST.has(impactV) ||
        !LIKELIHOOD_ALLOWLIST.has(likelihoodV) ||
        !STATUS_ALLOWLIST.has(statusV)) {
      logger.info({ id: cap(id) }, 'dropped threat row with off-allowlist enum (B2)');
      continue;
    }
    if (!id || !threat) continue;

    threats.push({
      id: cap(id),
      title: cap(threat),
      actor: actorV,
      surface: cap(surface),
      asset: cap(asset),
      impact: impactV,
      likelihood: likelihoodV,
      status: statusV,
      controls: cap(cols[8] ?? ''),
      evidence: cap(cols[9] ?? ''),
    });
  }
  return threats;
}

// ─── Bootstrap prompt (harness 8-section contract, adapted) ───────────────────

const THREATMODEL_SYSTEM_PROMPT = `You are a security architect performing STATIC threat modeling of a source tree.
You read source via the read_file/list_files/grep tools; you NEVER build, run, fuzz, or modify the target, and never make network requests.

WORKFLOW (follow strictly — do NOT over-explore):
- You are given a structured code-analysis summary in the user message (languages, frameworks, endpoints, auth patterns, dataflow source→sink). BASE THE THREAT MODEL PRIMARILY ON THAT SUMMARY. It already identifies the entry points, trust boundaries, and assets you need.
- Treat file-reading as TARGETED CONFIRMATION ONLY, not open-ended discovery. You may read AT MOST ~10-15 specific files to confirm an entry point, auth check, or trust boundary named in the summary. Do NOT survey the whole tree, do NOT enumerate directories you don't need, do NOT grep broadly "just to be thorough".
- After those targeted reads (or immediately, if the summary is sufficient), you MUST STOP reading and emit the complete THREAT_MODEL.md. Do not keep investigating once you have enough to write 3+ threats.

Produce a THREAT_MODEL.md document with EXACTLY these eight sections, headings verbatim and in order:

# Threat Model: <system name>

## 1. System context
One to three paragraphs of prose: what the system is, what it does, who uses it, where it runs.

## 2. Assets
Markdown table: | asset | description | sensitivity |  (sensitivity ∈ low, medium, high, critical)

## 3. Entry points & trust boundaries
Markdown table: | entry_point | description | trust_boundary | reachable_assets |

## 4. Threats
Markdown table with EXACTLY this column order:
| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
- id: T1, T2, ...
- threat: one sentence, active voice, names the outcome (survives a one-line patch).
- actor ∈ remote_unauth, remote_auth, adjacent_network, local_user, local_admin, supply_chain, insider
- surface: which section-3 entry point(s) this traverses.
- asset: which section-2 asset(s) this compromises.
- impact ∈ low, medium, high, critical, existential
- likelihood ∈ very_rare, rare, possible, likely, almost_certain
- status ∈ unmitigated, partially_mitigated, mitigated, risk_accepted
- controls: current mitigations, or "none".
- evidence: CVE/issue/commit ids that instantiate this threat, or empty.
Sort rows by (impact, likelihood) descending.

## 5. Deprioritized
Markdown table: | threat | reason |

## 6. Open questions
Bullet list of what the code could not answer.

## 7. Provenance
- mode: bootstrap
- date: <today>
- target: <path>
- inputs: code analysis + static source review
- owner: unset

## 8. Recommended mitigations
Markdown table: | mitigation | threat_ids | closes_class | effort |  (closes_class ∈ yes, partial; effort ∈ S, M, L)

Output ONLY the THREAT_MODEL.md markdown — no preamble, no code fences around the whole document.

TERMINAL INSTRUCTION (BINDING): Your FINAL message MUST be the complete THREAT_MODEL.md in the exact 8-section format above — nothing else. No preamble, no "let me check…", no narration, no tool call. Emit ALL eight sections even if some are brief. Section 4 (Threats) MUST contain AT LEAST 3 threat rows derived from the code-analysis summary. If you have read a few files and still feel uncertain, STOP READING and write the model anyway from the summary — a complete model with brief sections is required; an unfinished investigation is a failure.`;

function buildSeedContext(ca: FullAnalysisResult | null): string {
  if (!ca) {
    return 'No code-analysis context available. Derive the model from the source tree directly using the tools.';
  }
  const r = ca.result;
  const langs = r.languages.map((l) => l.language).join(', ') || 'unknown';
  const frameworks = r.frameworks.map((f) => f.name ?? f.framework).join(', ') || 'none detected';
  const endpoints = r.endpoints
    .slice(0, 40)
    .map((e) => `${e.method} ${e.path} (${e.file})`.trim())
    .join('\n');
  const auth = r.authPatterns
    .slice(0, 20)
    .map((a) => `${a.type}${a.file ? ` @ ${a.file}` : ''}`)
    .join('\n');
  const flows = r.dataFlows
    .slice(0, 30)
    .map((d) => `${d.source.type}:${d.source.location} → ${d.sink.type}:${d.sink.location}`.trim())
    .join('\n');

  return [
    'Code Hardener pre-computed the following code-analysis summary (CA-001..010). This is your PRIMARY INPUT — base the threat model on it. Use the tools only to confirm a handful of specific entry points or trust boundaries named below; do NOT survey the whole tree.',
    `\nLanguages: ${langs}`,
    `Frameworks: ${frameworks}`,
    endpoints ? `\nEndpoints (untrusted-input entry points):\n${endpoints}` : '',
    auth ? `\nAuth patterns:\n${auth}` : '',
    flows ? `\nDataflow source→sink summary:\n${flows}` : '',
  ].filter(Boolean).join('\n');
}

// ─── Findings (info-level for unmitigated critical/high/existential) ──────────

const FINDING_IMPACTS = new Set<ParsedThreat['impact']>(['critical', 'high', 'existential']);

function threatsToFindings(threats: ParsedThreat[]): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  for (const t of threats) {
    if (t.status !== 'unmitigated') continue;
    if (!FINDING_IMPACTS.has(t.impact)) continue;
    findings.push({
      ruleId: `LLM-TM-${t.id}`,
      severity: 'info',
      // title/description are markdown-escaped at render time (Phase 3); still capped here per B2.
      title: cap(`Threat: ${t.title}`),
      description: cap(
        `Actor: ${t.actor}. Surface: ${t.surface}. Asset: ${t.asset}. ` +
        `Impact: ${t.impact}, likelihood: ${t.likelihood}, status: ${t.status}. ` +
        `Controls: ${t.controls || 'none'}.${t.evidence ? ` Evidence: ${t.evidence}.` : ''}`,
      ),
      filePath: null,
      lineNumber: null,
      columnNumber: null,
      codeSnippet: null,
      cweId: null,
      owaspCategory: null,
      fixAvailable: false,
      fixDescription: null,
      metadata: { stage: 'threat-model', threat: t },
    });
  }
  return findings;
}

// ─── DB helpers (parameterized sql only — §11 B2) ─────────────────────────────

interface StoredThreatModel {
  content: string;
  threats_json: string;
  source_inventory_hash: string;
  model_used: string;
}

async function loadStoredModel(projectId: string): Promise<StoredThreatModel | null> {
  const result = await db.execute(sql`
    SELECT content, threats_json, source_inventory_hash, model_used
    FROM threat_models
    WHERE project_id = ${projectId}
  `);
  if (result.rows.length === 0) return null;
  return result.rows[0] as unknown as StoredThreatModel;
}

/** Parse the stored threats_json, falling back to re-parsing the markdown. */
function threatsOfStored(stored: StoredThreatModel): ParsedThreat[] {
  try {
    return JSON.parse(stored.threats_json) as ParsedThreat[];
  } catch {
    return parseThreatsSection(stored.content);
  }
}

/** Build the "reused cached model" ScannerResult (zero API calls). */
function buildCachedResult(stored: StoredThreatModel, startTime: number): ScannerResult {
  return {
    scanner: 'llm-threatmodel',
    success: true,
    findings: threatsToFindings(threatsOfStored(stored)),
    duration: Date.now() - startTime,
    rawOutput: 'Reused cached threat model (inventory hash match — zero API calls).',
    evidence: {
      scanScope: 'Cached per-project threat model (no source transmitted this run)',
      checksPerformed: ['STRIDE threat enumeration', 'attack-surface mapping', 'threat-class generalization'],
      configuration: `model: ${stored.model_used} (cached)`,
    },
  };
}

async function isProjectOptedIn(projectId: string): Promise<boolean> {
  const result = await db.execute(sql`
    SELECT llm_analysis_enabled FROM projects WHERE id = ${projectId}
  `);
  if (result.rows.length === 0) return false;
  return (result.rows[0] as Record<string, unknown>).llm_analysis_enabled === true;
}

// ─── Scanner entry point ──────────────────────────────────────────────────────

export async function runLlmThreatmodel(_jobData: ScanJobData): Promise<ScannerResult> {
  const startTime = Date.now();

  // §11 R3 gate, in order: API key, then per-project opt-in.
  if (!llmVerifyEnabled) {
    return {
      scanner: 'llm-threatmodel',
      success: true,
      skipped: true,
      skipReason: 'no_llm_api_key',
      skipHint: 'Set ANTHROPIC_API_KEY to enable LLM threat modeling (Premium feature).',
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  try {
    const optedIn = await isProjectOptedIn(_jobData.projectId);
    if (!optedIn) {
      return {
        scanner: 'llm-threatmodel',
        success: true,
        skipped: true,
        skipReason: 'llm_not_opted_in',
        skipHint:
          'LLM analysis transmits project source code to the Anthropic API. ' +
          'Enable it per project (projects.llm_analysis_enabled) to opt in.',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    const inventoryHash = await computeInventoryHash(SCAN_TARGET);

    // Staleness: reuse a stored model with ZERO API calls on a hash match.
    const stored = await loadStoredModel(_jobData.projectId);
    if (stored && stored.source_inventory_hash === inventoryHash) {
      logger.info({ projectId: _jobData.projectId }, 'reusing cached threat model (inventory hash match)');
      return buildCachedResult(stored, startTime);
    }

    // §11 R2: reuse the scan-scoped budget threaded by runScanPipeline so the
    // ceiling is shared with the other LLM stages; fall back to a fresh budget so
    // the scanner remains runnable standalone (e.g. in tests).
    const budget = _jobData.llmBudget ?? new ScanTokenBudget(env.LLM_SCAN_MAX_TOTAL_TOKENS);
    if (budget.exhausted) {
      // A prior LLM stage already consumed the whole budget — do zero API work.
      return {
        scanner: 'llm-threatmodel',
        success: true,
        skipped: true,
        skipReason: 'llm_budget_exhausted',
        skipHint:
          'The scan-scoped LLM token budget (LLM_SCAN_MAX_TOTAL_TOKENS) was exhausted ' +
          'by an earlier LLM stage. Raise the budget to enable this stage.',
        findings: [],
        duration: Date.now() - startTime,
      };
    }

    // F6: serialize concurrent generation for the SAME project. Two scans that
    // both miss the cache would otherwise each call the API and double-upsert
    // (last-write-wins, wasted tokens). Acquire a per-project transaction-scoped
    // advisory lock; under it, RE-CHECK staleness (a peer scan may have just
    // generated) before spending any tokens. The lock auto-releases on
    // COMMIT/ROLLBACK. The LLM call runs while the lock is held — intentional, so
    // the peer waits rather than racing.
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // hashtext() maps the project_id text to the int4 pg_advisory_xact_lock expects.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [_jobData.projectId]);

      // Re-check under the lock: a peer scan may have generated a fresh model
      // while we waited to acquire it.
      const reStored = (await client.query(
        `SELECT content, threats_json, source_inventory_hash, model_used
         FROM threat_models WHERE project_id = $1`,
        [_jobData.projectId],
      )).rows[0] as StoredThreatModel | undefined;
      if (reStored && reStored.source_inventory_hash === inventoryHash) {
        await client.query('COMMIT');
        logger.info(
          { projectId: _jobData.projectId },
          'reusing cached threat model (peer generated under advisory lock)',
        );
        return buildCachedResult(reStored, startTime);
      }

      // Regenerate: seed with code analysis (reuse threaded jobData.codeAnalysis if present).
      const ca = _jobData.codeAnalysis ?? (await runCodeAnalysis(SCAN_TARGET));
      const seed = buildSeedContext(ca);

      const userPrompt =
        `${seed}\n\nBase the threat model on the summary above. You may read AT MOST ~10-15 specific files to confirm entry points or trust boundaries — do NOT survey the whole tree. Then your FINAL message MUST be the complete 8-section THREAT_MODEL.md (section 4 with at least 3 threat rows), nothing else.`;

      // FIX B (§11 R2 refinement): wrap the shared scan budget in a stage-scoped
      // sub-budget so threat-model generation is capped at LLM_THREATMODEL_MAX_TOKENS
      // (or the shared pool's remaining headroom, whichever is smaller) and cannot
      // drain the whole aggregate budget — leaving vuln-scan/triage/patch with
      // headroom. The ScopedTokenBudget still debits the shared `budget` on every
      // consume, so the R2 aggregate ceiling continues to count this stage's tokens.
      const stageBudget = new ScopedTokenBudget(budget, env.LLM_THREATMODEL_MAX_TOKENS);

      // FIX C (convergence): cap the threat-model agent's tool-use round trips at
      // LLM_THREATMODEL_MAX_ITERATIONS (default 14) — well below runBoundedAgent's
      // default of 25 — so it cannot exhaust the budget by wandering the tree on a
      // large repo. The agent is seeded with the CA-001..010 summary, so ~14
      // iterations is ample for a handful of targeted confirmation reads + a final
      // synthesis turn that emits the complete THREAT_MODEL.md. The stage/aggregate
      // token budgets remain the backstop; this adds hard iteration discipline so
      // the agent actually REACHES the terminal end_turn the FIX A validity gate
      // requires, instead of looping until max_iterations/budget_exhausted.
      const agent = await runBoundedAgent({
        systemPrompt: THREATMODEL_SYSTEM_PROMPT,
        userPrompt,
        model: env.LLM_THREATMODEL_MODEL,
        targetDir: SCAN_TARGET,
        maxIterations: env.LLM_THREATMODEL_MAX_ITERATIONS,
        maxTokens: 8192,
        // The final synthesis turn emits the full 8-section THREAT_MODEL.md, which
        // exceeds the default 30s per-request timeout on large repos. Give the
        // threat-model agent a longer per-request budget so synthesis completes.
        timeoutMs: env.LLM_THREATMODEL_REQUEST_TIMEOUT_MS,
        budget: stageBudget,
        signal: _jobData.llmAbortSignal, // F3: pipeline scanner-timeout abort
      });

      if (agent.stopReason === 'error' || !agent.finalText.trim()) {
        await client.query('ROLLBACK');
        return {
          scanner: 'llm-threatmodel',
          success: false,
          findings: [],
          duration: Date.now() - startTime,
          error: agent.error ?? 'Threat-model generation produced no output',
        };
      }

      const content = agent.finalText;

      // FIX A (CORE LIVE-DEFECT FIX): validate the generated content BEFORE any
      // persist/cache. The live failure was a budget/iteration-exhausted agent
      // whose last `finalText` was a 96-char mid-investigation narration line
      // ("Now let me check for input validation vulnerabilities...") with an
      // empty threats table. The scanner stored that as a valid THREAT_MODEL.md,
      // returned success, AND poisoned the staleness cache (the next scan would
      // hash-match and reuse the garbage). Guard: never write a row unless the
      // content is a structurally-complete, cleanly-finished document.
      if (!isValidThreatModel(content, agent.stopReason)) {
        await client.query('ROLLBACK'); // release the advisory lock; persist NOTHING.
        const exhausted = EXHAUSTION_STOP_REASONS.has(agent.stopReason);
        logger.warn(
          { projectId: _jobData.projectId, stopReason: agent.stopReason, chars: content.trim().length },
          'threat model incomplete — not persisting (cache not poisoned)',
        );
        return {
          scanner: 'llm-threatmodel',
          success: true,
          skipped: true,
          skipReason: exhausted ? 'llm_budget_exhausted' : 'llm_threatmodel_incomplete',
          skipHint: exhausted
            ? 'The threat-model stage ran out of LLM token/iteration budget before ' +
              'emitting a complete THREAT_MODEL.md on this (large) repo. Raise ' +
              'LLM_THREATMODEL_MAX_TOKENS and/or LLM_SCAN_MAX_TOTAL_TOKENS, then re-scan.'
            : 'The model could not produce a structurally-complete threat model ' +
              '(missing required sections or too short). No threat model was stored.',
          findings: [],
          duration: Date.now() - startTime,
        };
      }

      // §8: parse failure → store markdown anyway, threats_json '[]'.
      let threats: ParsedThreat[] = [];
      try {
        threats = parseThreatsSection(content);
      } catch (parseErr) {
        logger.warn(
          { error: parseErr instanceof Error ? parseErr.message : 'parse error' },
          'section-4 parse failed — storing markdown with empty threats_json',
        );
        threats = [];
      }

      // Upsert on the SAME locked connection so the write is inside the
      // advisory-lock transaction.
      await client.query(
        `INSERT INTO threat_models
           (project_id, content, threats_json, source_inventory_hash, model_used, generated_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (project_id) DO UPDATE SET
           content = EXCLUDED.content,
           threats_json = EXCLUDED.threats_json,
           source_inventory_hash = EXCLUDED.source_inventory_hash,
           model_used = EXCLUDED.model_used,
           updated_at = NOW()`,
        [_jobData.projectId, content, JSON.stringify(threats), inventoryHash, env.LLM_THREATMODEL_MODEL],
      );
      await client.query('COMMIT');

      logger.info(
        { projectId: _jobData.projectId, threats: threats.length, iterations: agent.iterations },
        'threat model regenerated and upserted',
      );

      return {
        scanner: 'llm-threatmodel',
        success: true,
        findings: threatsToFindings(threats),
        duration: Date.now() - startTime,
        rawOutput: `Generated threat model: ${threats.length} threats parsed.`,
        evidence: {
          scanScope: 'Static LLM threat model of the source tree',
          checksPerformed: ['STRIDE threat enumeration', 'attack-surface mapping', 'threat-class generalization'],
          configuration: `model: ${env.LLM_THREATMODEL_MODEL}`,
        },
      };
    } catch (genErr) {
      // Release the advisory lock by rolling back, then rethrow to the outer
      // handler which returns the structured success:false result.
      try { await client.query('ROLLBACK'); } catch { /* connection already broken */ }
      throw genErr;
    } finally {
      client.release();
    }
  } catch (error) {
    // §8/§12: never throw out — return success:false with the message.
    logger.error({ error: error instanceof Error ? error.message : 'unknown' }, 'llm-threatmodel failed');
    return {
      scanner: 'llm-threatmodel',
      success: false,
      findings: [],
      duration: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
