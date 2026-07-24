/**
 * LLM-Powered Exploit Verification (Premium Feature)
 *
 * Uses Claude Haiku to verify whether "likely" or "confirmed" findings
 * are actually exploitable by constructing a step-by-step exploitation
 * path analysis. Inspired by OpenAnt's adversarial verification technique
 * but at ~100x lower cost per finding.
 *
 * Requirements:
 *   - ANTHROPIC_API_KEY must be set
 *   - Only runs on Enterprise plan (gate enforced by caller)
 *   - Only processes confirmed/likely findings (skip theoretical/unlikely)
 *   - Hard cap per scan: LLM_VERIFY_MAX_FINDINGS (default 10)
 *
 * Runs asynchronously post-scan to avoid blocking scan completion.
 */

import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import { env, llmVerifyEnabled } from '../../config/env.js';


const logger = createLogger('llm-verifier');

export interface LLMVerificationResult {
  verified: boolean;
  reasoning: string;
  confidence: number;
  exploitSteps?: string[];
}

const VERIFICATION_PROMPT = `You are a security engineer performing exploit verification. Your task is to determine if a security finding is actually exploitable given the code context.

Rules:
- Do NOT assume you have shell access or can run commands
- Do NOT assume network access to the target
- You MUST construct an explicit step-by-step exploitation path
- If any step requires an unreasonable assumption, the finding is NOT verified
- Be precise about what an attacker would need to control

Finding:
Title: {title}
Severity: {severity}
Scanner: {scanner}
Rule: {ruleId}
CWE: {cweId}
File: {filePath}:{lineNumber}
Description: {description}

Code Context:
\`\`\`
{codeContext}
\`\`\`

{dataflowContext}

Respond in JSON format:
{
  "verified": boolean,
  "confidence": number (0.0-1.0),
  "reasoning": "One paragraph explaining why this is or is not exploitable",
  "exploitSteps": ["Step 1: ...", "Step 2: ..."] // only if verified=true
}`;

/**
 * Call the Anthropic API to verify a finding.
 */
async function callAnthropicAPI(prompt: string): Promise<LLMVerificationResult> {
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY not configured');
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: env.LLM_VERIFY_MODEL,
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Anthropic API error ${response.status}: ${errorText}`);
  }

  const result = await response.json() as {
    content: Array<{ type: string; text: string }>;
  };

  const text = result.content[0]?.text || '{}';

  // Extract JSON from response (may be wrapped in markdown code blocks)
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error('No JSON found in LLM response');
  }

  const parsed = JSON.parse(jsonMatch[0]) as LLMVerificationResult;
  return {
    verified: parsed.verified ?? false,
    reasoning: parsed.reasoning || 'No reasoning provided',
    confidence: Math.min(1, Math.max(0, parsed.confidence ?? 0.5)),
    exploitSteps: parsed.exploitSteps,
  };
}

/**
 * Build the verification prompt for a finding.
 */
function buildPrompt(
  finding: {
    title: string;
    severity: string;
    scanner: string;
    ruleId: string | null;
    cweId: string | null;
    filePath: string | null;
    lineNumber: number | null;
    description: string;
    codeSnippet: string | null;
  },
  dataflowContext: string | null,
): string {
  return VERIFICATION_PROMPT
    .replace('{title}', finding.title)
    .replace('{severity}', finding.severity)
    .replace('{scanner}', finding.scanner)
    .replace('{ruleId}', finding.ruleId || 'N/A')
    .replace('{cweId}', finding.cweId || 'N/A')
    .replace('{filePath}', finding.filePath || 'N/A')
    .replace('{lineNumber}', String(finding.lineNumber || 'N/A'))
    .replace('{description}', finding.description)
    .replace('{codeContext}', finding.codeSnippet || 'No code snippet available')
    .replace('{dataflowContext}', dataflowContext
      ? `Dataflow Analysis:\n${dataflowContext}`
      : 'No dataflow analysis available for this finding.');
}

/**
 * Verify a single finding with LLM analysis.
 * Updates the finding in the database with verification results.
 */
export async function verifyFindingWithLLM(
  findingId: string,
): Promise<LLMVerificationResult | null> {
  if (!llmVerifyEnabled) return null;

  try {
    // Fetch finding details
    const result = await db.execute(sql`
      SELECT title, severity, scanner, rule_id, cwe_id, file_path, line_number,
             description, code_snippet, metadata, exploitability
      FROM findings WHERE id = ${findingId}
    `);

    if (result.rows.length === 0) return null;

    const row = result.rows[0] as Record<string, unknown>;

    // Only verify confirmed/likely findings
    if (row.exploitability !== 'confirmed' && row.exploitability !== 'likely') {
      return null;
    }

    const metadata = (row.metadata || {}) as Record<string, unknown>;
    const enrichment = metadata.enrichment as Record<string, unknown> | undefined;
    const dataflowContext = enrichment?.sanitizationEvidence as string | null;

    const prompt = buildPrompt(
      {
        title: row.title as string,
        severity: row.severity as string,
        scanner: row.scanner as string,
        ruleId: row.rule_id as string | null,
        cweId: row.cwe_id as string | null,
        filePath: row.file_path as string | null,
        lineNumber: row.line_number as number | null,
        description: row.description as string,
        codeSnippet: row.code_snippet as string | null,
      },
      dataflowContext,
    );

    const verification = await callAnthropicAPI(prompt);

    // Update finding with LLM verification results
    const updatedMetadata = {
      ...metadata,
      llmVerification: {
        verified: verification.verified,
        reasoning: verification.reasoning,
        confidence: verification.confidence,
        exploitSteps: verification.exploitSteps,
        model: env.LLM_VERIFY_MODEL,
        verifiedAt: new Date().toISOString(),
      },
    };

    await db.execute(sql`
      UPDATE findings
      SET llm_verified = ${verification.verified},
          metadata = ${JSON.stringify(updatedMetadata)}
      WHERE id = ${findingId}
    `);

    logger.info(
      {
        findingId,
        verified: verification.verified,
        confidence: verification.confidence,
      },
      'LLM verification completed'
    );

    return verification;
  } catch (error) {
    logger.warn(
      { error: error instanceof Error ? error.message : 'Unknown error', findingId },
      'LLM verification failed (non-fatal)'
    );
    return null;
  }
}

/**
 * Verify top findings for a scan using LLM analysis.
 * Only processes confirmed/likely findings, capped at LLM_VERIFY_MAX_FINDINGS.
 */
export async function verifyTopFindingsForScan(scanId: string): Promise<number> {
  if (!llmVerifyEnabled) return 0;

  const maxFindings = env.LLM_VERIFY_MAX_FINDINGS;

  // Fetch top confirmed/likely findings for this scan
  const result = await db.execute(sql`
    SELECT id FROM findings
    WHERE scan_id = ${scanId}
      AND exploitability IN ('confirmed', 'likely')
      AND llm_verified IS NULL
      AND status = 'open'
    ORDER BY
      CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
      CASE exploitability WHEN 'confirmed' THEN 1 ELSE 2 END
    LIMIT ${maxFindings}
  `);

  let verified = 0;
  for (const row of result.rows) {
    const findingId = (row as Record<string, unknown>).id as string;
    const verResult = await verifyFindingWithLLM(findingId);
    if (verResult) verified++;
  }

  if (verified > 0) {
    logger.info({ scanId, verified, total: result.rows.length }, 'LLM verification batch completed');
  }

  return verified;
}
