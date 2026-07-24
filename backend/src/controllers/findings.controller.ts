import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import { calculateQualityScore } from '../services/assurance/quality-score.js';

const logger = createLogger('findings-controller');

/**
 * Recompute and update the scan's findings_count JSONB, score, and quality_level
 * from live findings data. Called after any finding status change.
 */
export async function refreshScanFindingsCount(scanId: string): Promise<void> {
  // Raw counts: ALL findings regardless of status (for score_raw)
  const rawResult = await db.execute(sql`
    SELECT
      COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high') as high,
      COUNT(*) FILTER (WHERE f.severity = 'medium') as medium,
      COUNT(*) FILTER (WHERE f.severity = 'low') as low,
      COUNT(*) FILTER (WHERE f.severity = 'info') as info,
      COUNT(*) as total
    FROM findings f
    WHERE f.scan_id = ${scanId}
  `);

  const rawRow = rawResult.rows[0] as Record<string, unknown>;
  const rawCounts = {
    critical: parseInt(rawRow.critical as string) || 0,
    high: parseInt(rawRow.high as string) || 0,
    medium: parseInt(rawRow.medium as string) || 0,
    low: parseInt(rawRow.low as string) || 0,
    info: parseInt(rawRow.info as string) || 0,
    total: parseInt(rawRow.total as string) || 0,
  };
  const { score: scoreRaw } = calculateQualityScore(rawCounts);

  // Adjusted counts: only open findings (for score)
  const adjResult = await db.execute(sql`
    SELECT
      COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status = 'open') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high'     AND f.status = 'open') as high,
      COUNT(*) FILTER (WHERE f.severity = 'medium'   AND f.status = 'open') as medium,
      COUNT(*) FILTER (WHERE f.severity = 'low'      AND f.status = 'open') as low,
      COUNT(*) FILTER (WHERE f.severity = 'info'     AND f.status = 'open') as info,
      COUNT(*) FILTER (WHERE f.status = 'open') as total
    FROM findings f
    WHERE f.scan_id = ${scanId}
  `);

  const adjRow = adjResult.rows[0] as Record<string, unknown>;
  const counts = {
    critical: parseInt(adjRow.critical as string) || 0,
    high: parseInt(adjRow.high as string) || 0,
    medium: parseInt(adjRow.medium as string) || 0,
    low: parseInt(adjRow.low as string) || 0,
    info: parseInt(adjRow.info as string) || 0,
    total: parseInt(adjRow.total as string) || 0,
  };
  const { score, qualityLevel } = calculateQualityScore(counts);

  await db.execute(sql`
    UPDATE scans
    SET findings_count = ${JSON.stringify({ ...counts, raw: rawCounts })}::jsonb,
        score = ${score},
        score_raw = ${scoreRaw},
        quality_level = ${qualityLevel},
        updated_at = NOW()
    WHERE id = ${scanId}
  `);

  // Also update the project's last_score if this is the latest scan
  await db.execute(sql`
    UPDATE projects
    SET last_score = ${score}, updated_at = NOW()
    WHERE id = (SELECT project_id FROM scans WHERE id = ${scanId})
      AND last_scan_id = ${scanId}
  `);
}

const FINDING_STATUSES = ['open', 'fixed', 'ignored', 'false_positive', 'deferred'] as const;
const DISMISSED_STATUSES = ['fixed', 'ignored', 'false_positive', 'deferred'] as const;

const updateFindingSchema = z.object({
  status: z.enum(FINDING_STATUSES).optional(),
  reason: z.string().max(500).optional(),
  comment: z.string().max(2000).optional(),
});

const bulkUpdateSchema = z.object({
  ids: z.array(z.string().uuid()),
  status: z.enum(FINDING_STATUSES),
  reason: z.string().max(500).optional(),
  comment: z.string().max(2000).optional(),
});

// Transform database row to API response format (camelCase)
function transformFinding(row: Record<string, unknown>) {
  return {
    id: row.id,
    scanId: row.scan_id,
    severity: row.severity,
    title: row.title,
    description: row.description,
    filePath: row.file_path || '',
    lineNumber: row.line_number || 0,
    scanner: row.tool_name || row.scanner || '',
    status: row.status,
    cwe: row.cwe_id || null,
    cve: row.cve_id || null,
    remediation: row.remediation,
    // Enrichment fields
    exploitability: row.exploitability || null,
    reachable: row.reachable ?? null,
    dataflowMatch: row.dataflow_match || null,
    llmVerified: row.llm_verified ?? null,
    project: {
      id: row.project_id,
      name: row.project_name || '',
    },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    dismissedAt: row.dismissed_at,
    dismissedBy: row.dismissed_by,
  };
}

export async function listFindings(req: Request, res: Response) {
  // Dashboard sends array params as repeated keys (e.g. statuses=open&statuses=fixed)
  // or comma-separated. Normalize to arrays.
  function toArray(val: unknown): string[] {
    if (!val) return [];
    if (Array.isArray(val)) return val.map(String);
    return String(val).split(',').map(s => s.trim()).filter(Boolean);
  }

  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    projectId: z.string().uuid().optional(),
    search: z.string().optional(),
  }).passthrough();
  const parsed = querySchema.parse(req.query);
  const { page, limit, projectId, search } = parsed;
  const offset = (page - 1) * limit;

  // Accept both singular and plural param names
  const severities = toArray(req.query.severity || req.query.severities);
  const statuses = toArray(req.query.status || req.query.statuses);
  const scanners = toArray(req.query.scanner || req.query.scanners);
  const projects = toArray(req.query.projects);
  const exploitabilities = toArray(req.query.exploitability || req.query.exploitabilities);
  const reachable = req.query.reachable as string | undefined;

  // Scope to latest completed scan per project (not all historical scans).
  // The scanId param overrides this to show findings for a specific scan.
  const scanId = (req.query.scanId as string) || undefined;

  // Build a CTE for the scan scope: either a specific scan, or the latest per project
  let scanScope;
  if (scanId) {
    scanScope = sql`SELECT ${scanId}::uuid AS id`;
  } else {
    // Latest completed scan per project owned by this user
    let projectFilter = sql`p.user_id = ${req.user!.id}`;
    if (projectId) {
      projectFilter = sql`${projectFilter} AND p.id = ${projectId}`;
    }
    if (projects.length > 0) {
      const projectList = sql.join(projects.map(p => sql`${p}::uuid`), sql`, `);
      projectFilter = sql`${projectFilter} AND p.id IN (${projectList})`;
    }
    scanScope = sql`
      SELECT DISTINCT ON (s.project_id) s.id
      FROM scans s
      JOIN projects p ON p.id = s.project_id
      WHERE ${projectFilter} AND s.status = 'completed'
      ORDER BY s.project_id, s.created_at DESC
    `;
  }

  let whereClause = sql`f.scan_id IN (SELECT id FROM scoped_scans)`;

  if (severities.length > 0) {
    const sevList = sql.join(severities.map(s => sql`${s}`), sql`, `);
    whereClause = sql`${whereClause} AND f.severity IN (${sevList})`;
  }
  if (statuses.length > 0) {
    const statusList = sql.join(statuses.map(s => sql`${s}`), sql`, `);
    whereClause = sql`${whereClause} AND f.status IN (${statusList})`;
  }
  if (scanners.length > 0) {
    const scannerList = sql.join(scanners.map(s => sql`${s}`), sql`, `);
    whereClause = sql`${whereClause} AND f.tool_name IN (${scannerList})`;
  }
  if (exploitabilities.length > 0) {
    const exploitList = sql.join(exploitabilities.map(e => sql`${e}`), sql`, `);
    whereClause = sql`${whereClause} AND f.exploitability IN (${exploitList})`;
  }
  if (reachable === 'true' || reachable === 'false') {
    whereClause = sql`${whereClause} AND f.reachable = ${reachable === 'true'}`;
  }
  if (search) {
    whereClause = sql`${whereClause} AND (f.title ILIKE ${'%' + search + '%'} OR f.description ILIKE ${'%' + search + '%'} OR f.file_path ILIKE ${'%' + search + '%'})`;
  }

  const [findings, countResult, summaryResult] = await Promise.all([
    db.execute(sql`
      WITH scoped_scans AS (${scanScope})
      SELECT f.*, p.name as project_name, s.project_id as project_id
      FROM findings f
      JOIN scans s ON s.id = f.scan_id
      JOIN projects p ON p.id = s.project_id
      WHERE ${whereClause}
      ORDER BY
        CASE f.severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        f.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      WITH scoped_scans AS (${scanScope})
      SELECT COUNT(*) as count FROM findings f
      WHERE ${whereClause}
    `),
    db.execute(sql`
      WITH scoped_scans AS (${scanScope})
      SELECT
        COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
        COUNT(*) FILTER (WHERE f.severity = 'high') as high,
        COUNT(*) FILTER (WHERE f.severity = 'medium') as medium,
        COUNT(*) FILTER (WHERE f.severity = 'low') as low,
        COUNT(*) FILTER (WHERE f.severity = 'info') as info,
        COUNT(*) as total
      FROM findings f
      WHERE ${whereClause}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);
  const summaryRow = summaryResult.rows[0] as Record<string, unknown>;
  const summary = {
    critical: parseInt(summaryRow.critical as string) || 0,
    high: parseInt(summaryRow.high as string) || 0,
    medium: parseInt(summaryRow.medium as string) || 0,
    low: parseInt(summaryRow.low as string) || 0,
    info: parseInt(summaryRow.info as string) || 0,
    total: parseInt(summaryRow.total as string) || 0,
  };

  // Transform findings to camelCase format
  const transformedFindings = findings.rows.map(row => transformFinding(row as Record<string, unknown>));

  return sendSuccess(res, transformedFindings, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  }, { summary });
}

export async function getFinding(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT f.*, p.name as project_name, s.trigger_type as scan_trigger, s.project_id as project_id
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${id}
    AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Finding not found');
  }

  const row = result.rows[0] as Record<string, unknown>;
  const metadata = (row.metadata || {}) as Record<string, unknown>;

  // Extract enrichment from scanner metadata
  const cvssScore = metadata.cvssScore as number | undefined;
  const cvssVector = metadata.cvssVector as string | undefined;
  const purl = metadata.purl as string | undefined;
  const dataSource = metadata.dataSource as string | undefined;
  const moreInfo = metadata.moreInfo as string | undefined;
  const urls = (metadata.urls || []) as string[];
  const testName = metadata.testName as string | undefined;

  // Parse package info from purl (e.g. "pkg:golang/stdlib@1.20.12")
  let packageName: string | undefined;
  let packageVersion: string | undefined;
  let packageType: string | undefined;
  if (purl) {
    const purlMatch = purl.match(/^pkg:([^/]+)\/([^@]+)@(.+)$/);
    if (purlMatch) {
      packageType = purlMatch[1];
      packageName = purlMatch[2];
      packageVersion = purlMatch[3];
    }
  }

  // Build references list from all available URL sources
  const references: string[] = [];
  if (dataSource) references.push(dataSource);
  if (moreInfo) references.push(moreInfo);
  references.push(...urls);

  return sendSuccess(res, {
    id: row.id,
    scanId: row.scan_id,
    severity: row.severity,
    title: row.title,
    description: row.description,
    descriptionSimple: row.description_simple,
    filePath: row.file_path || '',
    lineNumber: row.line_number || 0,
    columnNumber: row.column_number || 0,
    codeSnippet: row.code_snippet || '',
    cwe: row.cwe_id || null,
    owaspCategory: row.owasp_category || null,
    ruleId: row.rule_id || testName || null,
    scanner: row.tool_name || row.scanner || '',
    status: row.status,
    fixAvailable: row.fix_available || false,
    fixDescription: row.fix_description || '',
    fixCode: row.fix_code || '',
    // Enriched fields from metadata
    cvssScore: cvssScore ?? null,
    cvssVector: cvssVector || null,
    packageName: packageName || null,
    packageVersion: packageVersion || null,
    packageType: packageType || null,
    references,
    // Enrichment fields
    exploitability: row.exploitability || null,
    reachable: row.reachable ?? null,
    dataflowMatch: row.dataflow_match || null,
    llmVerified: row.llm_verified ?? null,
    // Project context
    projectId: row.project_id,
    projectName: row.project_name || '',
    scanTrigger: row.scan_trigger || null,
    // Timestamps
    createdAt: row.created_at,
    dismissedAt: row.dismissed_at,
    dismissedBy: row.dismissed_by,
    dismissedComment: row.dismissed_comment,
    dismissedReason: row.dismissed_reason,
    metadata,
  });
}

export async function updateFinding(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const validation = updateFindingSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { status, reason, comment } = validation.data;
  const isDismissing = status && (DISMISSED_STATUSES as readonly string[]).includes(status);

  // Verify ownership
  const existing = await db.execute(sql`
    SELECT f.id FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (existing.rows.length === 0) {
    throw new NotFoundError('Finding not found');
  }

  const result = await db.execute(sql`
    UPDATE findings
    SET status = COALESCE(${status}, status),
        dismissed_at = CASE WHEN ${isDismissing} THEN NOW() ELSE dismissed_at END,
        dismissed_by = CASE WHEN ${isDismissing} THEN ${req.user!.id} ELSE dismissed_by END,
        dismissed_reason = CASE WHEN ${isDismissing} THEN COALESCE(${reason || null}, dismissed_reason) ELSE dismissed_reason END,
        dismissed_comment = CASE WHEN ${isDismissing} THEN COALESCE(${comment || null}, dismissed_comment) ELSE dismissed_comment END
    WHERE id = ${id}
    RETURNING *
  `);

  // Refresh the scan's findings_count JSONB to reflect the status change
  if (result.rows.length > 0) {
    const scanId = (result.rows[0] as Record<string, unknown>).scan_id as string;
    await refreshScanFindingsCount(scanId);
  }

  logger.info({ findingId: id, newStatus: status }, 'Finding updated');

  return sendSuccess(res, result.rows[0]);
}

export async function bulkUpdateFindings(req: Request, res: Response) {
  const validation = bulkUpdateSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { ids, status, reason, comment } = validation.data;
  const isDismissing = (DISMISSED_STATUSES as readonly string[]).includes(status);

  // Build parameterized IN clause: each id becomes a separate bound parameter
  const idList = sql.join(ids.map(id => sql`${id}::uuid`), sql`, `);

  // Update only findings the user owns, return scan_id for refresh
  const result = await db.execute(sql`
    UPDATE findings
    SET status = ${status},
        dismissed_at = CASE WHEN ${isDismissing} THEN NOW() ELSE dismissed_at END,
        dismissed_by = CASE WHEN ${isDismissing} THEN ${req.user!.id} ELSE dismissed_by END,
        dismissed_reason = CASE WHEN ${isDismissing} THEN COALESCE(${reason || null}, dismissed_reason) ELSE dismissed_reason END,
        dismissed_comment = CASE WHEN ${isDismissing} THEN COALESCE(${comment || null}, dismissed_comment) ELSE dismissed_comment END
    WHERE id IN (${idList})
    AND scan_id IN (SELECT s.id FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.user_id = ${req.user!.id})
    RETURNING id, scan_id
  `);

  // Refresh findings_count for all affected scans
  const affectedScanIds = [...new Set(result.rows.map((r: any) => r.scan_id as string))];
  await Promise.all(affectedScanIds.map(scanId => refreshScanFindingsCount(scanId)));

  logger.info({ count: result.rows.length, status, scansRefreshed: affectedScanIds.length }, 'Bulk findings update');

  return sendSuccess(res, {
    updated: result.rows.length,
  });
}

/**
 * GET /api/v1/findings/:id/patches — LLM-generated candidate patches for a finding.
 *
 * §11 R5: ownership-scoped via candidate_patches → findings → scans → projects
 * filtered by user_id; uuid-validates :id; 404 on missing/not-owned (no existence
 * oracle). Patch rows are returned camelCase, ordered created_at DESC. The R4
 * "self-assessment / never auto-applied" labeling happens at render time, not here.
 */
export async function getFindingPatches(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Verify the finding exists AND is owned by this user (no existence oracle).
  const owned = await db.execute(sql`
    SELECT f.id FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE f.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (owned.rows.length === 0) {
    throw new NotFoundError('Finding not found');
  }

  const result = await db.execute(sql`
    SELECT cp.id, cp.finding_id, cp.scan_id, cp.patch_diff, cp.rationale,
           cp.validation_notes, cp.model_used, cp.status, cp.created_at
    FROM candidate_patches cp
    JOIN findings f ON f.id = cp.finding_id
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE cp.finding_id = ${id} AND p.user_id = ${req.user!.id}
    ORDER BY cp.created_at DESC
  `);

  const patches = result.rows.map((r) => {
    const row = r as Record<string, unknown>;
    return {
      id: row.id,
      findingId: row.finding_id,
      scanId: row.scan_id,
      patchDiff: row.patch_diff,
      rationale: row.rationale,
      validationNotes: row.validation_notes,
      modelUsed: row.model_used,
      status: row.status,
      createdAt: row.created_at,
    };
  });

  return sendSuccess(res, patches);
}

export async function getFindingStats(req: Request, res: Response) {
  const { projectId } = z.object({
    projectId: z.string().uuid().optional(),
  }).passthrough().parse(req.query);

  let whereClause = sql`s.project_id IN (SELECT id FROM projects WHERE user_id = ${req.user!.id})`;
  if (projectId) {
    whereClause = sql`${whereClause} AND s.project_id = ${projectId}`;
  }

  const result = await db.execute(sql`
    SELECT
      COUNT(*) FILTER (WHERE f.status = 'open') as open,
      COUNT(*) FILTER (WHERE f.status = 'fixed') as fixed,
      COUNT(*) FILTER (WHERE f.status = 'ignored') as ignored,
      COUNT(*) FILTER (WHERE f.status = 'false_positive') as false_positive,
      COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
      COUNT(*) FILTER (WHERE f.severity = 'high') as high,
      COUNT(*) FILTER (WHERE f.severity = 'medium') as medium,
      COUNT(*) FILTER (WHERE f.severity = 'low') as low,
      COUNT(*) FILTER (WHERE f.severity = 'info') as info,
      COUNT(*) as total
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    WHERE ${whereClause}
  `);

  return sendSuccess(res, result.rows[0]);
}

export async function getTopFindings(req: Request, res: Response) {
  const { limit } = z.object({
    limit: z.coerce.number().int().min(1).max(50).default(10),
  }).passthrough().parse(req.query);

  const result = await db.execute(sql`
    SELECT f.*, p.name as project_name
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    JOIN projects p ON p.id = s.project_id
    WHERE p.user_id = ${req.user!.id}
    AND f.status = 'open'
    AND f.severity IN ('critical', 'high')
    ORDER BY
      CASE f.severity WHEN 'critical' THEN 1 ELSE 2 END,
      f.created_at DESC
    LIMIT ${limit}
  `);

  return sendSuccess(res, result.rows);
}
