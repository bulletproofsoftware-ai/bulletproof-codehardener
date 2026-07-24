import { Queue, Worker, Job } from 'bullmq';
import { redisUrl } from '../../config/env.js';
import { createLogger } from '../../utils/logger.js';
import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { runScanPipeline } from '../scanners/pipeline.js';
import { calculateQualityScore } from '../assurance/quality-score.js';
import { createScanAttestation, signAttestation, storeAttestation } from '../assurance/attestation.js';
import { importScanToDefectDojo } from '../defectdojo/index.js';
import { translateFinding } from '../translator/plain-language.js';
import { generateFixDescription } from '../scanners/remediation.js';
import { env } from '../../config/env.js';
import { applySuppressions } from '../../controllers/suppressions.controller.js';
import { getFrameworkSuppressions, applyFrameworkSuppressions } from '../scanners/framework-suppressions.js';
import { buildReachabilityMap } from '../scanners/reachability.js';
import { enrichFinding, shouldAutoSuppress, hasNoConfirmedExploits, type EnrichmentResult } from '../scanners/finding-enrichment.js';
import { verifyTopFindingsForScan } from '../scanners/llm-verifier.js';
import { runTriageStage } from '../scanners/llm-triage.js';
import { generateCandidatePatches } from '../scanners/llm-patch.js';
import { llmVerifyEnabled } from '../../config/env.js';

const logger = createLogger('scan-queue');

/**
 * Batch-fetch all previously dismissed findings for a project in a single query.
 * Returns a Map keyed by fingerprint (scanner:ruleId:filePath) -> dismissed status.
 * This replaces per-finding queries (N+1) with one bulk lookup.
 */
export async function batchGetPriorDismissedStatuses(
  projectId: string,
  currentScanId: string,
): Promise<Map<string, string>> {
  const result = await db.execute(sql`
    SELECT DISTINCT ON (f.scanner, f.rule_id, f.file_path)
      f.scanner, f.rule_id, f.file_path, f.status
    FROM findings f
    WHERE f.project_id = ${projectId}
      AND f.scan_id != ${currentScanId}
      AND f.status IN ('ignored', 'false_positive', 'fixed', 'deferred')
    ORDER BY f.scanner, f.rule_id, f.file_path, f.dismissed_at DESC NULLS LAST
  `);

  const map = new Map<string, string>();
  for (const row of result.rows as Array<Record<string, unknown>>) {
    const key = `${row.scanner}:${row.rule_id ?? ''}:${row.file_path ?? ''}`;
    map.set(key, row.status as string);
  }
  return map;
}

/** Build a fingerprint key for dismissed-status lookup */
export function findingFingerprint(scanner: string, ruleId: string | null, filePath: string | null): string | null {
  if (!ruleId && !filePath) return null;
  return `${scanner}:${ruleId ?? ''}:${filePath ?? ''}`;
}

export interface ScanJobData {
  scanId: string;
  projectId: string;
  userId: string;
  profile: string;
  branch: string;
  commitSha?: string;
  repositoryUrl?: string;
  scanners: string[];
  options?: {
    depth?: 'shallow' | 'full';
    excludePatterns?: string[];
    failThreshold?: string;
    timeout?: number;
    parallel?: boolean;
    healthCheckTimeout?: number;
    /** Minimum mutation score (0-100) to pass without warnings. Default: 20 */
    mutationScoreThreshold?: number;
  };
  // DAST/runtime context (populated from project + per-scan overrides)
  targetUrl?: string;
  containerImage?: string;
  openapiSpecPath?: string;
  authConfig?: {
    loginUrl: string;
    usernameField: string;
    passwordField: string;
    username: string;
    password: string;           // Plaintext — only in-memory during scan execution
    csrfTokenSelector?: string;
    successIndicator: string;
  };
  registryCredentials?: {
    registry: string;
    username: string;
    password: string;           // Plaintext — only in-memory during scan execution
  };
  // Scan scope for incremental (PR) scans
  scope?: 'full' | 'incremental';
  prContext?: {
    changedFiles?: string[];
    baseBranch?: string;
    prNumber?: number;
  };
  // Auto-detected context (populated by detectProjectContext in pipeline)
  detectedSpecs?: import('../../types/index.js').DetectedProjectContext;
  // Code-analysis result threaded on in runScanPipeline (consumed by LLM scanners; §12)
  codeAnalysis?: import('../scanners/code-analysis.js').FullAnalysisResult | null;
  // Scan-scoped aggregate LLM token budget (spec §11 R2). Constructed ONCE per scan
  // in runScanPipeline and shared across all LLM stages so total cost is bounded.
  // In-process only — never serialized across the BullMQ/Redis job-data boundary.
  llmBudget?: import('../scanners/llm-agent.js').ScanTokenBudget;
  // F3: per-scanner abort signal threaded onto jobData by runOneScanner's timeout
  // race. When the scanner-level timeout wins, the controller is aborted so the
  // LLM agent loops stop issuing API calls (no orphaned agents draining the
  // shared budget). In-process only — never serialized across the job boundary,
  // like llmBudget. Set/cleared per runOneScanner invocation.
  llmAbortSignal?: AbortSignal;
}

// Parse Redis URL for connection
function getRedisConnection() {
  const url = new URL(redisUrl);
  return {
    host: url.hostname,
    port: parseInt(url.port) || 6379,
    password: url.password || undefined,
  };
}

const connection = getRedisConnection();

// Create queue
export const scanQueue = new Queue<ScanJobData>('scans', {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000,
    },
    removeOnComplete: 100,
    removeOnFail: 50,
  },
});

// Add job to queue
export async function addScanJob(data: ScanJobData): Promise<Job<ScanJobData>> {
  const job = await scanQueue.add('scan', data, {
    jobId: data.scanId,
    priority: data.profile === 'quick' ? 1 : data.profile === 'standard' ? 2 : 3,
  });

  logger.info({ scanId: data.scanId, jobId: job.id }, 'Scan job added to queue');

  return job;
}

// Get queue stats
export async function getQueueStats() {
  const [waiting, active, completed, failed] = await Promise.all([
    scanQueue.getWaitingCount(),
    scanQueue.getActiveCount(),
    scanQueue.getCompletedCount(),
    scanQueue.getFailedCount(),
  ]);

  return { waiting, active, completed, failed };
}

/**
 * Trigger n8n scan orchestrator workflow instead of running locally.
 * Falls back to local pipeline if n8n is unavailable.
 */
async function triggerN8nScanWorkflow(jobData: ScanJobData): Promise<boolean> {
  if (!env.N8N_ENABLED) return false;

  try {
    const webhookUrl = `${env.N8N_WEBHOOK_BASE}/scan-orchestrator`;
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.N8N_API_KEY ? { 'X-N8N-API-KEY': env.N8N_API_KEY } : {}),
      },
      body: JSON.stringify({
        scanId: jobData.scanId,
        projectId: jobData.projectId,
        userId: jobData.userId,
        profile: jobData.profile,
        branch: jobData.branch,
        commitSha: jobData.commitSha,
        scanners: jobData.scanners,
        callbackUrl: `http://backend:${env.PORT}/internal/findings/import`,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok) {
      const result = await response.json() as { executionId?: string };
      if (result.executionId) {
        await db.execute(sql`
          UPDATE scans SET n8n_execution_id = ${result.executionId} WHERE id = ${jobData.scanId}
        `);
      }
      logger.info({ scanId: jobData.scanId, executionId: result.executionId }, 'Scan delegated to n8n');
      return true;
    }

    logger.warn({ scanId: jobData.scanId, status: response.status }, 'n8n webhook failed, falling back to local');
    return false;
  } catch (error) {
    logger.warn({ error, scanId: jobData.scanId }, 'n8n unavailable, falling back to local pipeline');
    return false;
  }
}

// Create worker
export function createScanWorker() {
  const worker = new Worker<ScanJobData>(
    'scans',
    async (job) => {
      const { scanId, projectId } = job.data;

      logger.info({ scanId, jobId: job.id }, 'Processing scan job');

      try {
        // Update scan status to running
        await db.execute(sql`
          UPDATE scans
          SET status = 'running', started_at = NOW(), updated_at = NOW()
          WHERE id = ${scanId}
        `);

        // Try n8n delegation first
        const delegated = await triggerN8nScanWorkflow(job.data);
        if (delegated) {
          // n8n will handle the rest and call back
          return { delegatedToN8n: true };
        }

        // Run scan pipeline locally (fallback)
        const { scannerResults: results, codeAnalysis, llmBudget } = await runScanPipeline(job.data);

        // Build reachability map from code analysis (if available)
        const reachability = codeAnalysis
          ? await buildReachabilityMap(codeAnalysis.result.endpoints, '/scan-target')
          : null;

        // Track all findings (for score_raw) and open-only (for adjusted score)
        let rawFindings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        let totalFindings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
        let totalDuration = 0;
        let deduplicatedCount = 0;
        const enrichmentResults = new Map<string, EnrichmentResult>();

        // Batch-fetch all prior dismissed statuses in ONE query (replaces per-finding N+1)
        const dismissedMap = await batchGetPriorDismissedStatuses(projectId, scanId);

        // Deduplicate findings within this scan — same scanner+rule+title+file+line = same finding
        const seenFindings = new Set<string>();
        let inScanDuplicates = 0;

        for (const result of results) {
          totalDuration += result.duration;

          for (const finding of result.findings) {
            // Deduplicate: skip if we've already seen this exact finding in this scan
            const dedupKey = `${result.scanner}:${finding.ruleId}:${finding.title}:${finding.filePath ?? ''}:${finding.lineNumber ?? ''}`;
            if (seenFindings.has(dedupKey)) {
              inScanDuplicates++;
              continue;
            }
            seenFindings.add(dedupKey);

            // O(1) lookup against pre-fetched dismissed statuses
            const fp = findingFingerprint(result.scanner, finding.ruleId, finding.filePath);
            const priorStatus = fp ? dismissedMap.get(fp) ?? null : null;

            let effectiveStatus = priorStatus || 'open';

            // Count ALL findings for raw score
            rawFindings[finding.severity]++;
            rawFindings.total++;

            // Enrich finding with code analysis context (if available)
            let enrichment: EnrichmentResult | null = null;
            if (codeAnalysis && reachability && effectiveStatus === 'open') {
              enrichment = enrichFinding(finding, result.scanner, codeAnalysis.result, reachability);

              // Auto-suppress if dataflow analysis confirms sanitization
              const { suppress, reason } = shouldAutoSuppress(enrichment);
              if (suppress) {
                effectiveStatus = 'false_positive';
                enrichment.suppressionReason = reason;
              }
            }

            // Only count open findings toward adjusted severity totals
            if (effectiveStatus === 'open') {
              totalFindings[finding.severity]++;
              totalFindings.total++;
            } else {
              deduplicatedCount++;
            }

            // Translate finding to plain language
            const translated = translateFinding(
              finding.title,
              finding.description,
              finding.severity,
              finding.cweId,
              finding.owaspCategory,
              result.scanner
            );

            // Generate actionable remediation guidance
            const fixDescription = generateFixDescription({
              scanner: result.scanner,
              ruleId: finding.ruleId,
              cweId: finding.cweId,
              title: finding.title,
              description: finding.description,
              originalFix: finding.fixDescription,
            });

            // Build metadata with enrichment data
            const metadata: Record<string, unknown> = {
              ...finding.metadata,
              actionRequired: translated.actionRequired,
              riskExplanation: translated.riskExplanation,
            };
            if (enrichment) {
              metadata.enrichment = {
                reachable: enrichment.reachable,
                reachableFrom: enrichment.reachableFrom,
                dataflowMatch: enrichment.dataflowMatch,
                sanitizationEvidence: enrichment.sanitizationEvidence,
                exploitability: enrichment.exploitability,
              };
            }

            // Build dismissed reason if auto-suppressed by enrichment
            const dismissedReason = enrichment?.suppressionReason || null;

            // Insert finding with carried-forward status if previously dismissed
            // Wrapped in try/catch to handle unique constraint violations from idx_findings_unique_per_scan
            try {
              const insertResult = await db.execute(sql`
                INSERT INTO findings (
                  scan_id, project_id, scanner, rule_id, severity, status,
                  title, description, description_simple,
                  file_path, line_number, column_number,
                  code_snippet, cwe_id, owasp_category, fix_available, fix_description,
                  exploitability, reachable, dataflow_match,
                  metadata,
                  dismissed_reason, dismissed_at
                ) VALUES (
                  ${scanId}, ${projectId}, ${result.scanner}, ${finding.ruleId},
                  ${finding.severity}, ${effectiveStatus}, ${finding.title},
                  ${finding.description}, ${translated.descriptionSimple},
                  ${finding.filePath}, ${finding.lineNumber}, ${finding.columnNumber},
                  ${finding.codeSnippet}, ${finding.cweId}, ${finding.owaspCategory},
                  ${finding.fixAvailable || fixDescription !== null}, ${fixDescription},
                  ${enrichment?.exploitability || null},
                  ${enrichment?.reachable ?? null},
                  ${enrichment?.dataflowMatch || null},
                  ${JSON.stringify(metadata)},
                  ${dismissedReason},
                  ${dismissedReason ? sql`NOW()` : null}
                )
                RETURNING id
              `);

              // Track enrichment for risk score bonus calculation
              if (enrichment && insertResult.rows.length > 0) {
                const findingId = (insertResult.rows[0] as Record<string, unknown>).id as string;
                enrichmentResults.set(findingId, enrichment);
              }
            } catch (insertErr: unknown) {
              // Unique constraint violation (23505) = duplicate finding, skip silently
              if ((insertErr as Record<string, unknown>)?.code === '23505') {
                inScanDuplicates++;
                continue;
              }
              throw insertErr;
            }
          }
        }

        if (inScanDuplicates > 0) {
          logger.info({ scanId, inScanDuplicates }, 'Duplicate findings deduplicated within scan');
        }

        if (deduplicatedCount > 0) {
          logger.info({ scanId, deduplicatedCount }, 'Findings auto-dismissed from prior scan resolutions');
        }

        // Apply framework-aware suppressions (runs BEFORE user suppression rules)
        let frameworkSuppressedCount = 0;
        if (codeAnalysis) {
          const fwSuppressions = getFrameworkSuppressions(codeAnalysis.result.frameworks);
          frameworkSuppressedCount = await applyFrameworkSuppressions(scanId, projectId, fwSuppressions);
          if (frameworkSuppressedCount > 0) {
            logger.info({ scanId, frameworkSuppressedCount }, 'Framework auto-suppressions applied');
          }
        }

        // Apply project-level suppression rules to auto-triage findings
        const suppressedCount = await applySuppressions(scanId, projectId);
        if (suppressedCount > 0) {
          logger.info({ scanId, suppressedCount }, 'Findings auto-suppressed by project rules');
        }

        // ── F1: LLM mutation stages BEFORE counts/score/attestation ──────────
        // runTriageStage and verifyTopFindingsForScan suppress FPs/dups and
        // recalibrate severity — they MUTATE finding status/severity. They must
        // run before we re-query counts, compute the score, and sign the
        // attestation, otherwise the score and the signed attestation describe a
        // pre-triage finding set that no longer matches the DB. Each stage stays
        // non-fatal: a throw is caught and logged, and the score then proceeds
        // from the pre-(failed-)stage findings exactly as before. Gated by
        // llmVerifyEnabled (opt-in checked again inside each stage).
        // Candidate-patch generation is deliberately NOT here — it does not mutate
        // findings or the score, so it runs LAST (after attestation).
        if (llmVerifyEnabled) {
          // 1. Triage: N-vote verify, cross-scanner dedupe, FP exclusion, recalibration.
          //    Sets llm_verified on findings it handles so verifyTopFindingsForScan skips them (§12).
          try {
            // §11 R2: pass the scan-scoped budget already partially consumed by the
            // in-pipeline LLM scanners so triage shares the single aggregate ceiling.
            const triage = await runTriageStage(scanId, llmBudget ?? undefined);
            if (triage.triaged > 0 || triage.duplicates > 0 || triage.falsePositives > 0 || triage.recalibrated > 0) {
              logger.info({ scanId, ...triage }, 'LLM triage stage completed');
            }
          } catch (triageError) {
            logger.warn({ error: triageError, scanId }, 'LLM triage failed (non-fatal)');
          }

          // 2. Exploit verification — naturally skips llm_verified-set findings.
          try {
            const llmVerified = await verifyTopFindingsForScan(scanId);
            if (llmVerified > 0) {
              logger.info({ scanId, llmVerified }, 'LLM exploit verification completed');
            }
          } catch (llmError) {
            logger.warn({ error: llmError, scanId }, 'LLM verification failed (non-fatal)');
          }
        }

        // Re-query BOTH counters from DB — the authoritative source of truth.
        // In-memory counters drift because:
        //   1. rawFindings counts findings that fail the DB unique constraint
        //   2. totalFindings misses status changes from framework suppressions
        //   3. User suppression rules change open→suppressed after insertion
        //   4. F1: LLM triage/verification (run just above) suppress FPs/dups and
        //      recalibrate severity, changing open-severity counts in the DB
        const countsResult = await db.execute(sql`
          SELECT
            COUNT(*) FILTER (WHERE severity = 'critical') as raw_critical,
            COUNT(*) FILTER (WHERE severity = 'high')     as raw_high,
            COUNT(*) FILTER (WHERE severity = 'medium')   as raw_medium,
            COUNT(*) FILTER (WHERE severity = 'low')      as raw_low,
            COUNT(*) FILTER (WHERE severity = 'info')     as raw_info,
            COUNT(*)                                       as raw_total,
            COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open') as adj_critical,
            COUNT(*) FILTER (WHERE severity = 'high'     AND status = 'open') as adj_high,
            COUNT(*) FILTER (WHERE severity = 'medium'   AND status = 'open') as adj_medium,
            COUNT(*) FILTER (WHERE severity = 'low'      AND status = 'open') as adj_low,
            COUNT(*) FILTER (WHERE severity = 'info'     AND status = 'open') as adj_info,
            COUNT(*) FILTER (WHERE status = 'open')                           as adj_total
          FROM findings WHERE scan_id = ${scanId}
        `);
        const countsRow = countsResult.rows[0] as Record<string, unknown>;
        rawFindings = {
          critical: parseInt(countsRow.raw_critical as string) || 0,
          high: parseInt(countsRow.raw_high as string) || 0,
          medium: parseInt(countsRow.raw_medium as string) || 0,
          low: parseInt(countsRow.raw_low as string) || 0,
          info: parseInt(countsRow.raw_info as string) || 0,
          total: parseInt(countsRow.raw_total as string) || 0,
        };
        totalFindings = {
          critical: parseInt(countsRow.adj_critical as string) || 0,
          high: parseInt(countsRow.adj_high as string) || 0,
          medium: parseInt(countsRow.adj_medium as string) || 0,
          low: parseInt(countsRow.adj_low as string) || 0,
          info: parseInt(countsRow.adj_info as string) || 0,
          total: parseInt(countsRow.adj_total as string) || 0,
        };

        // Build scanners_executed summary with audit evidence
        const scannersExecuted = results.map(r => ({
          scanner: r.scanner,
          success: r.success,
          skipped: r.skipped || false,
          skipReason: r.skipReason || null,
          skipHint: r.skipHint || null,
          findings: r.findings.length,
          duration: r.duration,
          error: r.error || null,
          evidence: r.evidence || null,
        }));
        const successfulScanners = results.filter(r => r.success && !r.skipped).length;
        const skippedScanners = results.filter(r => r.skipped).length;

        // Compute security bonuses from scan results
        const successfulScannerNames = results.filter(r => r.success && !r.skipped).map(r => r.scanner);
        const scannerHasNoFindings = (name: string) =>
          results.find(r => r.scanner === name && r.success)?.findings.length === 0;

        // Check if project has used multiple profiles historically
        const profileHistoryResult = await db.execute(sql`
          SELECT COUNT(DISTINCT profile) as profile_count
          FROM scans
          WHERE project_id = ${projectId} AND status = 'completed'
        `);
        const profileCount = parseInt((profileHistoryResult.rows[0] as Record<string, unknown>).profile_count as string) || 0;

        // Check mutation testing score from stryker/mutmut/pitest evidence
        const mutationScanners = ['stryker', 'mutmut', 'pitest'];
        const mutationResult = results.find(r =>
          mutationScanners.includes(r.scanner) && r.success && !r.skipped
        );
        const mutationScore = mutationResult?.evidence?.configuration
          ? parseFloat(mutationResult.evidence.configuration.match(/score[:\s]*(\d+)/i)?.[1] || '0')
          : (mutationResult?.findings.length === 0 ? 100 : 0);

        const bonuses = {
          hasSbom: successfulScannerNames.includes('syft'),
          hasSignedAttestation: false, // updated after attestation signing below
          cleanSecrets: successfulScannerNames.includes('gitleaks') && scannerHasNoFindings('gitleaks'),
          cleanIac: successfulScannerNames.includes('checkov') && scannerHasNoFindings('checkov'),
          hasSupplyChainVerification: successfulScannerNames.some(s => ['cosign', 'in-toto'].includes(s)),
          multipleProfilesUsed: profileCount >= 2,
          highMutationScore: !!mutationResult && mutationScore >= 70,
          cleanPackageValidation: successfulScannerNames.includes('package-validator') && scannerHasNoFindings('package-validator'),
          cleanLicenseSnippets: successfulScannerNames.includes('scancode') && scannerHasNoFindings('scancode'),
          noConfirmedExploits: enrichmentResults.size > 0 && hasNoConfirmedExploits(enrichmentResults),
        };

        // Calculate raw score (all findings, for score_raw) and adjusted score (open findings only)
        // Compute test runner bonuses
        const testScanners = ['jest', 'pytest'];
        const testResults = results.filter(r => testScanners.includes(r.scanner) && r.success && !r.skipped);
        const allTestsPassing = testResults.length > 0 && testResults.every(r =>
          r.findings.filter(f => f.ruleId.endsWith('-FAIL') || f.ruleId.endsWith('-ERROR') || f.ruleId.endsWith('-NO-TESTS')).length === 0
        );
        const highTestCoverage = testResults.length > 0 && testResults.every(r => {
          if (!r.evidence?.configuration) return false;
          const match = r.evidence.configuration.match(/coverage[:\s]*(\d+)/i);
          return match ? parseFloat(match[1]) >= 80 : false;
        });

        const qualityBonuses = { ...bonuses, allTestsPassing, highTestCoverage };

        const { score: computedRawScore } = calculateQualityScore(rawFindings, qualityBonuses);
        let scoreRaw = computedRawScore;
        const { score: adjScore, qualityLevel: adjQualityLevel } = calculateQualityScore(totalFindings, qualityBonuses);
        let score = adjScore;
        let qualityLevel = adjQualityLevel;

        if (results.length === 0) {
          // No scanners ran at all — this is an error, not a clean scan
          score = 0;
          scoreRaw = 0;
          qualityLevel = 'critical' as typeof qualityLevel;
        } else if (successfulScanners === 0 && skippedScanners === results.length) {
          // Every scanner skipped — nothing was actually scanned
          score = 0;
          scoreRaw = 0;
          qualityLevel = 'unknown' as typeof qualityLevel;
        } else if (successfulScanners === 0) {
          // All scanners failed (not skipped) — can't determine security posture
          score = 0;
          scoreRaw = 0;
          qualityLevel = 'critical' as typeof qualityLevel;
        }

        // Build code analysis summary for the scans table
        const codeAnalysisSummary = codeAnalysis ? {
          languages: codeAnalysis.result.languages.map(l => l.language),
          frameworks: codeAnalysis.result.frameworks.map(f => f.name || f.framework),
          endpointCount: codeAnalysis.result.endpoints.length,
          authPatternCount: codeAnalysis.result.authPatterns.length,
          dataFlowCount: codeAnalysis.result.dataFlows.length,
          enrichedFindings: enrichmentResults.size,
          frameworkSuppressed: frameworkSuppressedCount,
          durationMs: codeAnalysis.metadata.durationMs,
        } : null;

        // Update scan with results (score_raw = raw score from all findings, score = adjusted)
        await db.execute(sql`
          UPDATE scans
          SET
            status = 'completed',
            score = ${score},
            score_raw = ${scoreRaw},
            quality_level = ${qualityLevel},
            findings_count = ${JSON.stringify({ ...totalFindings, raw: rawFindings })},
            scanners_executed = ${JSON.stringify(scannersExecuted)},
            code_analysis_summary = ${codeAnalysisSummary ? JSON.stringify(codeAnalysisSummary) : null},
            duration = ${totalDuration},
            completed_at = NOW(),
            updated_at = NOW()
          WHERE id = ${scanId}
        `);

        // Update project last scan info
        await db.execute(sql`
          UPDATE projects
          SET
            last_scan_id = ${scanId},
            last_scan_at = NOW(),
            last_score = ${score},
            updated_at = NOW()
          WHERE id = ${projectId}
        `);

        // Create and store attestation
        try {
          const projectResult = await db.execute(sql`
            SELECT name FROM projects WHERE id = ${projectId}
          `);
          const projectName = (projectResult.rows[0] as any)?.name || 'Unknown';

          const attestation = await createScanAttestation(
            scanId,
            projectId,
            projectName,
            {
              profile: job.data.profile,
              scannersUsed: results.map(r => r.scanner),
              startTime: new Date(Date.now() - totalDuration),
              endTime: new Date(),
              duration: totalDuration,
              findings: totalFindings,
              score,
              qualityLevel,
            }
          );

          // Try to sign with Sigstore (optional, may not be configured)
          const sigResult = await signAttestation(attestation);
          if (sigResult) {
            attestation.signature = sigResult.signature;
            attestation.signatureAlgorithm = sigResult.algorithm;
            attestation.certificate = sigResult.certificate;
            attestation.rekorLogId = sigResult.rekorLogId;

            // Recalculate score with attestation bonus if signing succeeded
            if (!qualityBonuses.hasSignedAttestation) {
              qualityBonuses.hasSignedAttestation = true;
              const recalc = calculateQualityScore(totalFindings, qualityBonuses);
              score = recalc.score;
              // Apply severity ceilings again
              if (results.length === 0 || (successfulScanners === 0 && skippedScanners === results.length) || successfulScanners === 0) {
                score = 0;
              }
              await db.execute(sql`
                UPDATE scans SET score = ${score} WHERE id = ${scanId}
              `);
            }
          } else {
            logger.warn({ scanId, attestationId: attestation.id }, 'Attestation stored UNSIGNED — no signing method available');
          }

          await storeAttestation(attestation);
          logger.info({ scanId, attestationId: attestation.id, signed: !!sigResult }, 'Attestation created');
        } catch (attestError) {
          logger.warn({ error: attestError, scanId }, 'Attestation creation failed (non-fatal)');
        }

        // Import to DefectDojo (non-fatal)
        try {
          const ddResult = await importScanToDefectDojo(scanId, projectId, results, {
            branch: job.data.branch,
            commitSha: job.data.commitSha,
            profile: job.data.profile,
          });
          if (ddResult) {
            logger.info(
              { scanId, engagementId: ddResult.engagementId, imported: ddResult.imported },
              'Results imported to DefectDojo'
            );
          }
        } catch (ddError) {
          logger.warn({ error: ddError, scanId }, 'DefectDojo import failed (non-fatal)');
        }

        // F1: Candidate patch generation runs LAST — after counts, score, and the
        // signed attestation. Patches never mutate finding status/severity or the
        // score, so ordering them here keeps them out of the scored/attested set
        // while still benefiting from the post-triage finding statuses. Non-fatal,
        // opt-in gated within the stage. (Triage + verification already ran above,
        // before the score/attestation, per F1.)
        if (llmVerifyEnabled) {
          try {
            // §11 R2: same shared budget — patch generation reports zero if the
            // earlier stages already exhausted it.
            const patches = await generateCandidatePatches(scanId, llmBudget ?? undefined);
            if (patches > 0) {
              logger.info({ scanId, patches }, 'LLM candidate patches generated');
            }
          } catch (patchError) {
            logger.warn({ error: patchError, scanId }, 'LLM patch generation failed (non-fatal)');
          }
        }

        logger.info(
          { scanId, score, findingsCount: totalFindings.total, duration: totalDuration },
          'Scan completed'
        );

        return { score, findingsCount: totalFindings.total };
      } catch (error) {
        logger.error({ error, scanId }, 'Scan job failed');

        await db.execute(sql`
          UPDATE scans
          SET status = 'failed', updated_at = NOW()
          WHERE id = ${scanId}
        `);

        throw error;
      }
    },
    {
      connection,
      concurrency: 5,
      limiter: {
        max: 10,
        duration: 60000,
      },
    }
  );

  worker.on('completed', (job) => {
    logger.info({ jobId: job.id, scanId: job.data.scanId }, 'Job completed');
  });

  worker.on('failed', (job, err) => {
    logger.error({ jobId: job?.id, scanId: job?.data.scanId, error: err }, 'Job failed');
  });

  worker.on('error', (err) => {
    logger.error({ error: err }, 'Worker error');
  });

  return worker;
}
