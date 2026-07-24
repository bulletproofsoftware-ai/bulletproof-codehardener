import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('suppressions-controller');

const createSuppressionSchema = z.object({
  projectId: z.string().uuid(),
  matchType: z.enum(['rule_id', 'scanner', 'cwe', 'title_pattern']),
  matchValue: z.string().min(1).max(500),
  targetStatus: z.enum(['deferred', 'false_positive', 'ignored']).default('deferred'),
  reason: z.string().max(500).optional(),
  comment: z.string().max(2000).optional(),
});

const updateSuppressionSchema = z.object({
  matchValue: z.string().min(1).max(500).optional(),
  targetStatus: z.enum(['deferred', 'false_positive', 'ignored']).optional(),
  reason: z.string().max(500).optional(),
  comment: z.string().max(2000).optional(),
  isActive: z.boolean().optional(),
});

export async function listSuppressions(req: Request, res: Response) {
  const { projectId } = z.object({ projectId: z.string().uuid().optional() }).passthrough().parse(req.query);

  let whereClause = sql`
    fs.project_id IN (SELECT id FROM projects WHERE user_id = ${req.user!.id})
  `;
  if (projectId) {
    whereClause = sql`${whereClause} AND fs.project_id = ${projectId}`;
  }

  const result = await db.execute(sql`
    SELECT fs.*, p.name as project_name
    FROM finding_suppressions fs
    JOIN projects p ON p.id = fs.project_id
    WHERE ${whereClause}
    ORDER BY fs.created_at DESC
  `);

  const suppressions = result.rows.map((row: any) => ({
    id: row.id,
    projectId: row.project_id,
    projectName: row.project_name,
    matchType: row.match_type,
    matchValue: row.match_value,
    targetStatus: row.target_status,
    reason: row.reason,
    comment: row.comment,
    isActive: row.is_active,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));

  return sendSuccess(res, suppressions);
}

export async function createSuppression(req: Request, res: Response) {
  const validation = createSuppressionSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { projectId, matchType, matchValue, targetStatus, reason, comment } = validation.data;

  // Verify project ownership
  const project = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${projectId} AND user_id = ${req.user!.id}
  `);
  if (project.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  const result = await db.execute(sql`
    INSERT INTO finding_suppressions (project_id, user_id, match_type, match_value, target_status, reason, comment)
    VALUES (${projectId}, ${req.user!.id}, ${matchType}, ${matchValue}, ${targetStatus}, ${reason || null}, ${comment || null})
    RETURNING *
  `);

  const row = result.rows[0] as any;
  logger.info({ suppressionId: row.id, projectId, matchType, matchValue }, 'Suppression rule created');

  return sendCreated(res, {
    id: row.id,
    projectId: row.project_id,
    matchType: row.match_type,
    matchValue: row.match_value,
    targetStatus: row.target_status,
    reason: row.reason,
    comment: row.comment,
    isActive: row.is_active,
    createdAt: row.created_at,
  });
}

export async function updateSuppression(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const validation = updateSuppressionSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.issues);
  }

  const { matchValue, targetStatus, reason, comment, isActive } = validation.data;

  const result = await db.execute(sql`
    UPDATE finding_suppressions
    SET match_value = COALESCE(${matchValue ?? null}, match_value),
        target_status = COALESCE(${targetStatus ?? null}, target_status),
        reason = COALESCE(${reason ?? null}, reason),
        comment = COALESCE(${comment ?? null}, comment),
        is_active = COALESCE(${isActive ?? null}, is_active)
    WHERE id = ${id}
    AND project_id IN (SELECT id FROM projects WHERE user_id = ${req.user!.id})
    RETURNING *
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Suppression rule not found');
  }

  const row = result.rows[0] as any;
  return sendSuccess(res, {
    id: row.id,
    projectId: row.project_id,
    matchType: row.match_type,
    matchValue: row.match_value,
    targetStatus: row.target_status,
    reason: row.reason,
    comment: row.comment,
    isActive: row.is_active,
    updatedAt: row.updated_at,
  });
}

export async function deleteSuppression(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    DELETE FROM finding_suppressions
    WHERE id = ${id}
    AND project_id IN (SELECT id FROM projects WHERE user_id = ${req.user!.id})
    RETURNING id
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Suppression rule not found');
  }

  logger.info({ suppressionId: id }, 'Suppression rule deleted');
  return sendSuccess(res, { deleted: true });
}

/**
 * Apply active suppression rules to findings for a given scan.
 * Called after findings are inserted during scan completion.
 */
export async function applySuppressions(scanId: string, projectId: string): Promise<number> {
  const result = await db.execute(sql`
    UPDATE findings f
    SET status = s.target_status,
        dismissed_reason = s.reason,
        dismissed_comment = s.comment,
        dismissed_at = NOW(),
        dismissed_by = s.user_id
    FROM finding_suppressions s
    WHERE f.scan_id = ${scanId}
      AND s.project_id = ${projectId}
      AND s.is_active = true
      AND f.status = 'open'
      AND (
        (s.match_type = 'rule_id' AND f.rule_id = s.match_value)
        OR (s.match_type = 'scanner' AND f.scanner = s.match_value)
        OR (s.match_type = 'cwe' AND f.cwe_id = s.match_value)
        OR (s.match_type = 'title_pattern' AND f.title ILIKE '%' || s.match_value || '%')
      )
    RETURNING f.id
  `);

  if (result.rows.length > 0) {
    logger.info({ scanId, projectId, suppressed: result.rows.length }, 'Auto-suppressed findings');
  }

  return result.rows.length;
}
