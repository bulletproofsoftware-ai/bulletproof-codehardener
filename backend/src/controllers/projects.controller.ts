import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendNoContent, sendValidationError } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import { syncProjectToDefectDojo } from '../services/defectdojo/index.js';
import { encryptAuthConfig } from '../services/crypto/credential-encryption.js';

const logger = createLogger('projects-controller');

// Transform database row to API response format (camelCase)
function transformProject(row: Record<string, unknown>) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    repositoryUrl: row.repo_url || null,
    repositoryProvider: row.repo_provider || null,
    defaultBranch: row.default_branch || 'main',
    lastScanId: row.last_scan_id || null,
    lastScanAt: row.last_scan_at || null,
    lastScore: row.last_score ?? null,
    targetUrl: row.target_url || null,
    containerImage: row.container_image || null,
    openapiSpecPath: row.openapi_spec_path || null,
    authConfigured: row.auth_config != null,
    registryCredentialsId: row.registry_credentials_id || null,
    scanCount: parseInt(row.scan_count as string) || 0,
    openFindings: parseInt(row.open_findings as string) || 0,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    recentScans: row.recent_scans || [],
  };
}

const createProjectSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  repositoryUrl: z.string().url().optional(),
  defaultBranch: z.string().default('main'),
  targetUrl: z.string().url().optional(),
  containerImage: z.string().max(500).optional(),
  openapiSpecPath: z.string().max(500).optional(),
});

const updateProjectSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  repositoryUrl: z.string().url().optional(),
  defaultBranch: z.string().optional(),
  targetUrl: z.string().url().nullable().optional(),
  containerImage: z.string().max(500).nullable().optional(),
  openapiSpecPath: z.string().max(500).nullable().optional(),
});

const authConfigSchema = z.object({
  loginUrl: z.string().url(),
  usernameField: z.string().min(1),
  passwordField: z.string().min(1),
  username: z.string().min(1),
  password: z.string().min(1),
  csrfTokenSelector: z.string().optional(),
  successIndicator: z.string().min(1),
});

export async function listProjects(req: Request, res: Response) {
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }).passthrough();
  const { page, limit } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  const [projects, countResult] = await Promise.all([
    db.execute(sql`
      SELECT p.*,
        (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) as scan_count,
        (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open') as open_findings
      FROM projects p
      WHERE p.user_id = ${req.user!.id}
      ORDER BY p.updated_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `),
    db.execute(sql`
      SELECT COUNT(*) as count FROM projects WHERE user_id = ${req.user!.id}
    `),
  ]);

  const total = parseInt((countResult.rows[0] as Record<string, unknown>).count as string);
  const transformedProjects = projects.rows.map(row => transformProject(row as Record<string, unknown>));

  return sendSuccess(res, transformedProjects, 200, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
}

export async function getProject(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT p.*,
      (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) as scan_count,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = p.id AND f.status = 'open') as open_findings,
      (SELECT json_agg(json_build_object(
        'id', s.id,
        'status', s.status,
        'score', s.score,
        'createdAt', s.created_at
      ) ORDER BY s.created_at DESC)
      FROM (SELECT * FROM scans WHERE project_id = p.id ORDER BY created_at DESC LIMIT 5) s) as recent_scans
    FROM projects p
    WHERE p.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  return sendSuccess(res, transformProject(result.rows[0] as Record<string, unknown>));
}

export async function createProject(req: Request, res: Response) {
  const validation = createProjectSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { name, description, repositoryUrl, defaultBranch, targetUrl, containerImage, openapiSpecPath } = validation.data;

  const result = await db.execute(sql`
    INSERT INTO projects (user_id, name, description, repo_url, default_branch, target_url, container_image, openapi_spec_path)
    VALUES (${req.user!.id}, ${name}, ${description || null}, ${repositoryUrl || null}, ${defaultBranch}, ${targetUrl || null}, ${containerImage || null}, ${openapiSpecPath || null})
    RETURNING *
  `);

  const newProject = result.rows[0] as Record<string, unknown>;
  logger.info({ projectId: newProject.id }, 'Project created');

  // Sync to DefectDojo (non-blocking)
  syncProjectToDefectDojo(
    newProject.id as string,
    name,
    description
  ).catch(err => logger.warn({ error: err }, 'DefectDojo sync failed (non-fatal)'));

  return sendCreated(res, transformProject(newProject));
}

export async function updateProject(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const validation = updateProjectSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  // Check ownership
  const existing = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${id} AND user_id = ${req.user!.id}
  `);

  if (existing.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  const updates = validation.data;

  // Check if any updates provided
  if (Object.keys(updates).length === 0) {
    const project = await db.execute(sql`SELECT * FROM projects WHERE id = ${id}`);
    return sendSuccess(res, transformProject(project.rows[0] as Record<string, unknown>));
  }

  // Build dynamic SET clauses. For nullable fields (targetUrl, containerImage, openapiSpecPath),
  // explicit null means "clear this field", undefined means "don't touch".
  // COALESCE won't work for clearing to NULL, so we handle nullable fields explicitly.
  const hasTargetUrl = 'targetUrl' in updates;
  const hasContainerImage = 'containerImage' in updates;
  const hasOpenapiSpecPath = 'openapiSpecPath' in updates;

  const result = await db.execute(sql`
    UPDATE projects
    SET name = COALESCE(${updates.name ?? null}, name),
        description = COALESCE(${updates.description ?? null}, description),
        repo_url = COALESCE(${updates.repositoryUrl ?? null}, repo_url),
        default_branch = COALESCE(${updates.defaultBranch ?? null}, default_branch),
        target_url = ${hasTargetUrl ? (updates.targetUrl ?? null) : sql`target_url`},
        container_image = ${hasContainerImage ? (updates.containerImage ?? null) : sql`container_image`},
        openapi_spec_path = ${hasOpenapiSpecPath ? (updates.openapiSpecPath ?? null) : sql`openapi_spec_path`},
        updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `);

  return sendSuccess(res, transformProject(result.rows[0] as Record<string, unknown>));
}

export async function deleteProject(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    DELETE FROM projects WHERE id = ${id} AND user_id = ${req.user!.id}
    RETURNING id
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  logger.info({ projectId: id }, 'Project deleted');

  return sendNoContent(res);
}

export async function updateAuthConfig(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const validation = authConfigSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  // Verify ownership
  const existing = await db.execute(sql`
    SELECT id FROM projects WHERE id = ${id} AND user_id = ${req.user!.id}
  `);

  if (existing.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  // Encrypt the password and store the whole auth config as JSONB
  const stored = encryptAuthConfig(validation.data);

  const result = await db.execute(sql`
    UPDATE projects
    SET auth_config = ${JSON.stringify(stored)}::jsonb,
        updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `);

  logger.info({ projectId: id }, 'Auth config updated');

  return sendSuccess(res, transformProject(result.rows[0] as Record<string, unknown>));
}

export async function deleteAuthConfig(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    UPDATE projects
    SET auth_config = NULL,
        updated_at = NOW()
    WHERE id = ${id} AND user_id = ${req.user!.id}
    RETURNING *
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  logger.info({ projectId: id }, 'Auth config deleted');

  return sendSuccess(res, transformProject(result.rows[0] as Record<string, unknown>));
}

export async function getProjectStats(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  const result = await db.execute(sql`
    SELECT
      (SELECT COUNT(*) FROM scans WHERE project_id = ${id}) as total_scans,
      (SELECT COUNT(*) FROM scans WHERE project_id = ${id} AND status = 'completed') as completed_scans,
      (SELECT AVG(score) FROM scans WHERE project_id = ${id} AND score IS NOT NULL) as avg_score,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = ${id}) as total_findings,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = ${id} AND f.status = 'open') as open_findings,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = ${id} AND f.severity = 'critical') as critical_findings,
      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.project_id = ${id} AND f.severity = 'high') as high_findings
    FROM projects p
    WHERE p.id = ${id} AND p.user_id = ${req.user!.id}
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Project not found');
  }

  return sendSuccess(res, result.rows[0]);
}
