/**
 * Internal API endpoints for n8n -> backend communication.
 * Auth: Internal API key (not user JWT).
 */

import { Router, Request, Response, NextFunction } from 'express';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { env } from '../config/env.js';
import { createLogger } from '../utils/logger.js';
import { SCANNER_MAP } from '../services/scanners/pipeline.js';
import { calculateQualityScore } from '../services/assurance/quality-score.js';
import { importScanToDefectDojo } from '../services/defectdojo/index.js';
import { batchGetPriorDismissedStatuses, findingFingerprint } from '../services/queue/scan.queue.js';
import { applySuppressions } from '../controllers/suppressions.controller.js';

const logger = createLogger('n8n-hooks');
const router = Router();

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Map an untrusted severity string from a request body onto a fixed key.
 *
 * The counter objects below are indexed by this result. Returning a literal
 * rather than the caller's own string means a payload such as
 * {"severity": "__proto__"} or {"severity": "total"} can never become the
 * property name being written — previously it created a junk key on the
 * counter object and, in the "total" case, silently corrupted the scan totals
 * that feed the quality score.
 */
function toSeverityKey(severity: unknown): SeverityKey | null {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'info': return 'info';
    default: return null;
  }
}

// Internal API key auth middleware
function internalAuth(req: Request, res: Response, next: NextFunction): void {
  const key = req.headers['x-internal-api-key'] as string;
  if (!key || key !== env.INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Invalid internal API key' });
    return;
  }
  next();
}

router.use(internalAuth);

/**
 * Execute a specific scanner
 * POST /internal/scanners/execute
 */
router.post('/scanners/execute', async (req: Request, res: Response): Promise<void> => {
  try {
    const { scanId, projectId, userId, scanner, branch, profile } = req.body;

    if (!scanId || !scanner) {
      res.status(400).json({ error: 'scanId and scanner are required' });
      return;
    }

    const runScanner = SCANNER_MAP[scanner];
    if (!runScanner) {
      res.status(400).json({ error: `Unknown scanner: ${scanner}` });
      return;
    }

    const result = await runScanner({
      scanId,
      projectId,
      userId,
      profile: profile || 'standard',
      branch: branch || 'main',
      scanners: [scanner],
    });

    res.json({
      scanner: result.scanner,
      success: result.success,
      findingsCount: result.findings.length,
      duration: result.duration,
      findings: result.findings,
      rawOutput: result.rawOutput,
      error: result.error,
    });
  } catch (error) {
    logger.error({ error }, 'Scanner execution failed');
    res.status(500).json({ error: 'Scanner execution failed' });
  }
});

/**
 * Bulk import findings from n8n scan results
 * POST /internal/findings/import
 */
router.post('/findings/import', async (req: Request, res: Response): Promise<void> => {
  try {
    const { scanId, projectId, results, score, qualityLevel, duration } = req.body;

    if (!scanId || !results) {
      res.status(400).json({ error: 'scanId and results are required' });
      return;
    }

    let totalFindings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let deduplicatedCount = 0;

    // Batch-fetch all prior dismissed statuses in ONE query (replaces per-finding N+1)
    const dismissedMap = await batchGetPriorDismissedStatuses(projectId, scanId);

    // Insert findings (with deduplication from prior dismissed findings)
    for (const result of results) {
      for (const finding of result.findings || []) {
        // O(1) lookup against pre-fetched dismissed statuses
        const fp = findingFingerprint(result.scanner, finding.ruleId, finding.filePath);
        const priorStatus = fp ? dismissedMap.get(fp) ?? null : null;

        const effectiveStatus = priorStatus || 'open';

        if (effectiveStatus === 'open') {
          const severityKey = toSeverityKey(finding.severity);
          if (severityKey) {
            totalFindings[severityKey]++;
          }
          totalFindings.total++;
        } else {
          deduplicatedCount++;
        }

        await db.execute(sql`
          INSERT INTO findings (
            scan_id, project_id, scanner, rule_id, severity, status,
            title, description, file_path, line_number, column_number,
            code_snippet, cwe_id, owasp_category, fix_available, fix_description, metadata
          ) VALUES (
            ${scanId}, ${projectId}, ${result.scanner}, ${finding.ruleId},
            ${finding.severity}, ${effectiveStatus}, ${finding.title}, ${finding.description},
            ${finding.filePath}, ${finding.lineNumber}, ${finding.columnNumber},
            ${finding.codeSnippet}, ${finding.cweId}, ${finding.owaspCategory},
            ${finding.fixAvailable}, ${finding.fixDescription},
            ${JSON.stringify(finding.metadata || {})}
          )
        `);
      }
    }

    if (deduplicatedCount > 0) {
      logger.info({ scanId, deduplicatedCount }, 'Findings auto-dismissed from prior scan resolutions');
    }

    // Apply project-level suppression rules to auto-triage findings
    const suppressedCount = await applySuppressions(scanId, projectId);
    if (suppressedCount > 0) {
      logger.info({ scanId, suppressedCount }, 'Findings auto-suppressed by project rules');
      // Recalculate adjusted counts from DB since suppressions changed open status
      const adjResult = await db.execute(sql`
        SELECT
          COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open') as critical,
          COUNT(*) FILTER (WHERE severity = 'high'     AND status = 'open') as high,
          COUNT(*) FILTER (WHERE severity = 'medium'   AND status = 'open') as medium,
          COUNT(*) FILTER (WHERE severity = 'low'      AND status = 'open') as low,
          COUNT(*) FILTER (WHERE severity = 'info'     AND status = 'open') as info,
          COUNT(*) FILTER (WHERE status = 'open') as total
        FROM findings WHERE scan_id = ${scanId}
      `);
      const adjRow = adjResult.rows[0] as Record<string, unknown>;
      totalFindings = {
        critical: parseInt(adjRow.critical as string) || 0,
        high: parseInt(adjRow.high as string) || 0,
        medium: parseInt(adjRow.medium as string) || 0,
        low: parseInt(adjRow.low as string) || 0,
        info: parseInt(adjRow.info as string) || 0,
        total: parseInt(adjRow.total as string) || 0,
      };
    }

    // Calculate raw score (all findings before triage) and adjusted score (open only)
    const rawFindings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    for (const result of results) {
      for (const finding of result.findings || []) {
        const severityKey = toSeverityKey(finding.severity);
        if (severityKey) {
          rawFindings[severityKey]++;
        }
        rawFindings.total++;
      }
    }
    const { score: rawScore } = calculateQualityScore(rawFindings);
    const finalScore = score || calculateQualityScore(totalFindings).score;
    const finalQualityLevel = qualityLevel || calculateQualityScore(totalFindings).qualityLevel;

    // Update scan
    await db.execute(sql`
      UPDATE scans
      SET status = 'completed',
          score = ${finalScore},
          score_raw = ${rawScore},
          quality_level = ${finalQualityLevel},
          findings_count = ${JSON.stringify({ ...totalFindings, raw: rawFindings })},
          duration = ${duration || 0},
          completed_at = NOW(),
          updated_at = NOW()
      WHERE id = ${scanId}
    `);

    // Update project
    await db.execute(sql`
      UPDATE projects
      SET last_scan_id = ${scanId}, last_scan_at = NOW(), last_score = ${finalScore}, updated_at = NOW()
      WHERE id = ${projectId}
    `);

    // Import to DefectDojo
    try {
      await importScanToDefectDojo(scanId, projectId, results);
    } catch (ddError) {
      logger.warn({ error: ddError }, 'DefectDojo import from n8n failed (non-fatal)');
    }

    res.json({
      scanId,
      imported: totalFindings.total,
      score: finalScore,
      qualityLevel: finalQualityLevel,
    });
  } catch (error) {
    logger.error({ error }, 'Findings import failed');
    res.status(500).json({ error: 'Import failed' });
  }
});

/**
 * Evaluate findings against policy rules
 * POST /internal/policies/evaluate
 */
router.post('/policies/evaluate', async (req: Request, res: Response): Promise<void> => {
  try {
    const { projectId, scanId, findings } = req.body;

    // Get active policies for the project owner
    const policies = await db.execute(sql`
      SELECT p.* FROM policies p
      JOIN projects proj ON proj.user_id = p.user_id
      WHERE proj.id = ${projectId} AND p.is_active = true
    `);

    const violations: Array<{ policy: string; rule: string; severity: string; message: string }> = [];
    let shouldBlock = false;

    for (const policy of policies.rows as Record<string, unknown>[]) {
      const rules = await db.execute(sql`
        SELECT * FROM policy_rules WHERE policy_id = ${policy.id} AND enabled = true ORDER BY order_index
      `);

      for (const rule of rules.rows as Record<string, unknown>[]) {
        const condition = rule.condition as Record<string, unknown>;
        const ruleType = rule.rule_type as string;

        if (ruleType === 'severity_threshold') {
          const threshold = condition.severity as string;
          const maxAllowed = (condition.max_allowed as number) || 0;
          const count = (findings || []).filter(
            (f: Record<string, unknown>) => f.severity === threshold
          ).length;

          if (count > maxAllowed) {
            violations.push({
              policy: policy.name as string,
              rule: `Max ${maxAllowed} ${threshold} findings`,
              severity: threshold,
              message: rule.message as string || `Found ${count} ${threshold} findings (max: ${maxAllowed})`,
            });
            if (rule.action === 'block') shouldBlock = true;
          }
        }
      }
    }

    res.json({
      projectId,
      scanId,
      passed: violations.length === 0,
      shouldBlock,
      violations,
    });
  } catch (error) {
    logger.error({ error }, 'Policy evaluation failed');
    res.status(500).json({ error: 'Policy evaluation failed' });
  }
});

/**
 * Create an attestation (called by n8n post-scan workflow)
 * POST /internal/attestations/create
 */
router.post('/attestations/create', async (req: Request, res: Response): Promise<void> => {
  try {
    const { scanId, projectId, predicate } = req.body;

    const result = await db.execute(sql`
      INSERT INTO attestations (scan_id, predicate, attestation_type, subject_name, subject_digest)
      VALUES (
        ${scanId},
        ${JSON.stringify(predicate)},
        'https://codehardener.com/scan/v1',
        ${`project:${projectId}`},
        ${`scan:${scanId}`}
      )
      RETURNING id
    `);

    res.json({ id: (result.rows[0] as Record<string, unknown>).id });
  } catch (error) {
    logger.error({ error }, 'Attestation creation failed');
    res.status(500).json({ error: 'Attestation creation failed' });
  }
});

/**
 * Get project scanner config (what scanners to run for a profile)
 * GET /internal/projects/:id/config
 */
router.get('/projects/:id/config', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;

    const result = await db.execute(sql`
      SELECT id, name, repo_url, default_branch, defectdojo_product_id
      FROM projects WHERE id = ${id}
    `);

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Project not found' });
      return;
    }

    const project = result.rows[0] as Record<string, unknown>;

    res.json({
      project,
      availableScanners: Object.keys(SCANNER_MAP).filter(s => !['semgrep', 'eslint'].includes(s)),
    });
  } catch (error) {
    logger.error({ error }, 'Config fetch failed');
    res.status(500).json({ error: 'Failed to get config' });
  }
});

export { router as n8nHooksRoutes };
