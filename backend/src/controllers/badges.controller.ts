import { Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import { pool } from '../db/client.js';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';

const logger = createLogger('badges-controller');

const escHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Color thresholds for security scores
const SCORE_COLORS = {
  excellent: { min: 90, color: 'brightgreen' },
  good: { min: 70, color: 'green' },
  fair: { min: 50, color: 'yellow' },
  poor: { min: 30, color: 'orange' },
  critical: { min: 0, color: 'red' },
};

interface Badge {
  id: string;
  user_id: string;
  project_id: string;
  type: string;
  style: string;
  label: string | null;
  config: Record<string, unknown>;
  token: string;
  is_public: boolean;
  created_at: Date;
  updated_at: Date;
  project_name?: string;
}

// Public badge endpoint (no auth required)
export async function getPublicBadge(req: Request, res: Response) {
  const { token } = z.object({ token: z.string().min(1) }).parse(req.params);

  const result = await pool.query<Badge>(
    `SELECT b.*, p.name as project_name
     FROM badges b
     JOIN projects p ON p.id = b.project_id
     WHERE b.token = $1 AND b.is_public = true`,
    [token]
  );

  const badge = result.rows[0];
  if (!badge) {
    return apiError(res, 'Badge not found', 404);
  }

  const badgeData = await generateBadgeData(badge);
  const svg = generateBadgeSVG(badgeData, badge.style);

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  return res.send(svg);
}

// List badges
export async function listBadges(req: Request, res: Response) {
  const userId = req.user!.id;
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    projectId: z.string().uuid().optional(),
  }).passthrough();
  const { page, limit, projectId } = querySchema.parse(req.query);
  const offset = (page - 1) * limit;

  let whereClause = 'WHERE b.user_id = $1';
  const params: unknown[] = [userId];
  let paramIndex = 2;

  if (projectId) {
    whereClause += ` AND b.project_id = $${paramIndex++}`;
    params.push(projectId);
  }

  const countResult = await pool.query<{ count: string }>(
    `SELECT COUNT(*) as count FROM badges b ${whereClause}`,
    params
  );
  const total = parseInt(countResult.rows[0]?.count ?? '0', 10);

  const badgesResult = await pool.query<Badge>(
    `SELECT b.*, p.name as project_name
     FROM badges b
     JOIN projects p ON p.id = b.project_id
     ${whereClause}
     ORDER BY b.created_at DESC
     LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
    [...params, limit, offset]
  );

  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:4000';

  const badges = badgesResult.rows.map((b) => ({
    id: b.id,
    projectId: b.project_id,
    projectName: b.project_name,
    type: b.type,
    style: b.style,
    label: b.label,
    token: b.token,
    isPublic: b.is_public,
    url: `${baseUrl}/api/v1/badges/public/${b.token}`,
    createdAt: b.created_at.toISOString(),
  }));

  return apiSuccess(res, {
    data: badges,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

// Get single badge
export async function getBadge(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const result = await pool.query<Badge>(
    `SELECT b.*, p.name as project_name
     FROM badges b
     JOIN projects p ON p.id = b.project_id
     WHERE b.id = $1 AND b.user_id = $2`,
    [id, userId]
  );

  const b = result.rows[0];
  if (!b) {
    return apiError(res, 'Badge not found', 404);
  }

  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:4000';
  const badgeUrl = `${baseUrl}/api/v1/badges/public/${b.token}`;

  return apiSuccess(res, {
    id: b.id,
    projectId: b.project_id,
    projectName: b.project_name,
    type: b.type,
    style: b.style,
    label: b.label,
    config: b.config,
    token: b.token,
    isPublic: b.is_public,
    url: badgeUrl,
    markdown: `![${b.label ?? b.type}](${badgeUrl})`,
    html: `<img src="${escHtml(badgeUrl)}" alt="${escHtml(b.label ?? b.type)}" />`,
    createdAt: b.created_at.toISOString(),
    updatedAt: b.updated_at.toISOString(),
  });
}

// Create badge
export async function createBadge(req: Request, res: Response) {
  const userId = req.user!.id;
  const { projectId, type, style = 'flat', label, config } = req.body;

  // Verify project ownership
  const projectResult = await pool.query(
    'SELECT id FROM projects WHERE id = $1 AND user_id = $2',
    [projectId, userId]
  );

  if (projectResult.rows.length === 0) {
    return apiError(res, 'Project not found', 404);
  }

  const token = crypto.randomBytes(16).toString('hex');

  const result = await pool.query<Badge>(
    `INSERT INTO badges (user_id, project_id, type, style, label, config, token)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [userId, projectId, type, style, label ?? null, config ?? {}, token]
  );

  const badge = result.rows[0];
  if (!badge) {
    return apiError(res, 'Failed to create badge', 500);
  }

  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:4000';

  logger.info({ badgeId: badge.id, userId }, 'Badge created');

  return apiSuccess(res, {
    id: badge.id,
    projectId: badge.project_id,
    type: badge.type,
    style: badge.style,
    token: badge.token,
    url: `${baseUrl}/api/v1/badges/public/${badge.token}`,
    createdAt: badge.created_at.toISOString(),
  }, 201);
}

// Update badge
export async function updateBadge(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;
  const { label, style, config, isPublic } = req.body;

  const existingResult = await pool.query(
    'SELECT id FROM badges WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Badge not found', 404);
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (label !== undefined) {
    updates.push(`label = $${paramIndex++}`);
    values.push(label);
  }
  if (style !== undefined) {
    updates.push(`style = $${paramIndex++}`);
    values.push(style);
  }
  if (config !== undefined) {
    updates.push(`config = $${paramIndex++}`);
    values.push(config);
  }
  if (isPublic !== undefined) {
    updates.push(`is_public = $${paramIndex++}`);
    values.push(isPublic);
  }

  if (updates.length === 0) {
    return apiError(res, 'No fields to update', 400);
  }

  updates.push(`updated_at = NOW()`);
  values.push(id);

  const result = await pool.query<Badge>(
    `UPDATE badges SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
    values
  );

  const badge = result.rows[0];
  logger.info({ badgeId: id, userId }, 'Badge updated');

  return apiSuccess(res, {
    id: badge!.id,
    label: badge!.label,
    style: badge!.style,
    isPublic: badge!.is_public,
    updatedAt: badge!.updated_at.toISOString(),
  });
}

// Delete badge
export async function deleteBadge(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const existingResult = await pool.query(
    'SELECT id FROM badges WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Badge not found', 404);
  }

  await pool.query('DELETE FROM badges WHERE id = $1', [id]);

  logger.info({ badgeId: id, userId }, 'Badge deleted');

  return apiSuccess(res, { message: 'Badge deleted successfully' });
}

// Regenerate badge token
export async function regenerateBadgeToken(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const existingResult = await pool.query(
    'SELECT id FROM badges WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'Badge not found', 404);
  }

  const token = crypto.randomBytes(16).toString('hex');

  await pool.query(
    'UPDATE badges SET token = $1, updated_at = NOW() WHERE id = $2',
    [token, id]
  );

  const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:4000';

  logger.info({ badgeId: id, userId }, 'Badge token regenerated');

  return apiSuccess(res, {
    token,
    url: `${baseUrl}/api/v1/badges/public/${token}`,
  });
}

// Preview badge
export async function previewBadge(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const result = await pool.query<Badge>(
    `SELECT b.*, p.name as project_name
     FROM badges b
     JOIN projects p ON p.id = b.project_id
     WHERE b.id = $1 AND b.user_id = $2`,
    [id, userId]
  );

  const badge = result.rows[0];
  if (!badge) {
    return apiError(res, 'Badge not found', 404);
  }

  const badgeData = await generateBadgeData(badge);
  const svg = generateBadgeSVG(badgeData, badge.style);

  res.setHeader('Content-Type', 'image/svg+xml');
  return res.send(svg);
}

async function generateBadgeData(badge: Badge): Promise<{
  label: string;
  message: string;
  color: string;
}> {
  const label = badge.label ?? badge.type.replace(/-/g, ' ');

  switch (badge.type) {
    case 'security-score': {
      const result = await pool.query<{ total: string; fixed: string }>(
        `SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE f.status = 'fixed') as fixed
         FROM findings f
         JOIN scans s ON s.id = f.scan_id
         WHERE s.project_id = $1`,
        [badge.project_id]
      );

      const row = result.rows[0];
      const total = parseInt(row?.total ?? '0', 10);
      const fixed = parseInt(row?.fixed ?? '0', 10);
      const score = total === 0 ? 100 : Math.round((fixed / total) * 100);

      let color = 'red';
      for (const [, threshold] of Object.entries(SCORE_COLORS)) {
        if (score >= threshold.min) {
          color = threshold.color;
          break;
        }
      }

      return { label, message: `${score}%`, color };
    }

    case 'scan-status': {
      const result = await pool.query<{ status: string }>(
        `SELECT status FROM scans
         WHERE project_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [badge.project_id]
      );

      const scanRow = result.rows[0];
      if (!scanRow) {
        return { label, message: 'no scans', color: 'lightgrey' };
      }

      const statusColors: Record<string, string> = {
        completed: 'brightgreen',
        running: 'blue',
        pending: 'yellow',
        failed: 'red',
      };

      return { label, message: scanRow.status, color: statusColors[scanRow.status] ?? 'lightgrey' };
    }

    case 'findings-count': {
      const result = await pool.query<{ count: string }>(
        `SELECT COUNT(*) as count
         FROM findings f
         JOIN scans s ON s.id = f.scan_id
         WHERE s.project_id = $1 AND f.status = 'open'`,
        [badge.project_id]
      );

      const count = parseInt(result.rows[0]?.count ?? '0', 10);
      let color = 'brightgreen';
      if (count > 0) color = 'yellow';
      if (count > 10) color = 'orange';
      if (count > 50) color = 'red';

      return { label, message: count.toString(), color };
    }

    case 'last-scan': {
      const result = await pool.query<{ created_at: Date }>(
        `SELECT created_at FROM scans
         WHERE project_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [badge.project_id]
      );

      const lastScanRow = result.rows[0];
      if (!lastScanRow) {
        return { label, message: 'never', color: 'lightgrey' };
      }

      const daysSince = Math.floor((Date.now() - lastScanRow.created_at.getTime()) / (1000 * 60 * 60 * 24));

      let message: string;
      let color: string;

      if (daysSince === 0) {
        message = 'today';
        color = 'brightgreen';
      } else if (daysSince === 1) {
        message = 'yesterday';
        color = 'green';
      } else if (daysSince < 7) {
        message = `${daysSince} days ago`;
        color = 'yellow';
      } else if (daysSince < 30) {
        message = `${Math.floor(daysSince / 7)} weeks ago`;
        color = 'orange';
      } else {
        message = `${Math.floor(daysSince / 30)} months ago`;
        color = 'red';
      }

      return { label, message, color };
    }

    default:
      return { label, message: 'unknown', color: 'lightgrey' };
  }
}

function generateBadgeSVG(data: { label: string; message: string; color: string }, style: string): string {
  const colors: Record<string, string> = {
    brightgreen: '#4c1',
    green: '#97ca00',
    yellow: '#dfb317',
    orange: '#fe7d37',
    red: '#e05d44',
    blue: '#007ec6',
    lightgrey: '#9f9f9f',
    grey: '#555',
  };

  // Sanitize color: only allow known colors or valid hex codes
  const rawColor = colors[data.color] ?? data.color;
  const bgColor = /^#[0-9a-fA-F]{3,6}$/.test(rawColor) ? rawColor : '#9f9f9f';
  const safeLabel = escHtml(data.label);
  const safeMessage = escHtml(data.message);
  const labelWidth = data.label.length * 6.5 + 10;
  const messageWidth = data.message.length * 6.5 + 10;
  const totalWidth = labelWidth + messageWidth;

  if (style === 'for-the-badge') {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="28">
      <rect width="${labelWidth}" height="28" fill="#555"/>
      <rect x="${labelWidth}" width="${messageWidth}" height="28" fill="${bgColor}"/>
      <text x="${labelWidth / 2}" y="18" fill="#fff" font-family="Verdana,sans-serif" font-size="10" font-weight="bold" text-anchor="middle">${safeLabel.toUpperCase()}</text>
      <text x="${labelWidth + messageWidth / 2}" y="18" fill="#fff" font-family="Verdana,sans-serif" font-size="10" font-weight="bold" text-anchor="middle">${safeMessage.toUpperCase()}</text>
    </svg>`;
  }

  const radius = style === 'flat-square' ? 0 : 3;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
    <linearGradient id="b" x2="0" y2="100%">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="a">
      <rect width="${totalWidth}" height="20" rx="${radius}" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#a)">
      <rect width="${labelWidth}" height="20" fill="#555"/>
      <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="${bgColor}"/>
      <rect width="${totalWidth}" height="20" fill="url(#b)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
      <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${safeLabel}</text>
      <text x="${labelWidth / 2}" y="14">${safeLabel}</text>
      <text x="${labelWidth + messageWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${safeMessage}</text>
      <text x="${labelWidth + messageWidth / 2}" y="14">${safeMessage}</text>
    </g>
  </svg>`;
}
