import { Request, Response } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import * as argon2 from 'argon2';
import { pool } from '../db/client.js';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';

const logger = createLogger('api-keys-controller');

interface ApiKey {
  id: string;
  user_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  permissions: string[];
  is_active: boolean;
  last_used_at: Date | null;
  expires_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

// Available permissions
const AVAILABLE_PERMISSIONS = [
  'projects:read',
  'projects:write',
  'projects:delete',
  'scans:read',
  'scans:write',
  'findings:read',
  'findings:write',
  'attestations:read',
  'attestations:write',
  'attestations:delete',
  'policies:read',
  'policies:write',
  'policies:delete',
  'webhooks:read',
  'webhooks:write',
  'webhooks:delete',
  'reports:read',
  'reports:write',
  'badges:read',
  'admin',
];

// Get available permissions
export async function getAvailablePermissions(_req: Request, res: Response) {
  return apiSuccess(res, { permissions: AVAILABLE_PERMISSIONS });
}

// List API keys
export async function listApiKeys(req: Request, res: Response) {
  const userId = req.user!.id;
  const querySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    isActive: z.enum(['true', 'false']).optional(),
  }).passthrough();
  const { page, limit: rawLimit, isActive: isActiveStr } = querySchema.parse(req.query);
  const limit = Math.min(rawLimit, 100);
  const isActive = isActiveStr === 'true' ? true : isActiveStr === 'false' ? false : undefined;
  const offset = (page - 1) * limit;

  let whereClause = 'WHERE user_id = $1';
  const params: unknown[] = [userId];
  let paramIndex = 2;

  if (isActive !== undefined) {
    whereClause += ` AND is_active = $${paramIndex++}`;
    params.push(isActive);
  }

  const countResult = await pool.query<{ count: string }>(
    `SELECT COUNT(*) as count FROM api_keys ${whereClause}`,
    params
  );
  const total = parseInt(countResult.rows[0]?.count ?? '0', 10);

  const keysResult = await pool.query<ApiKey>(
    `SELECT * FROM api_keys ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
    [...params, limit, offset]
  );

  const keys = keysResult.rows.map((k) => ({
    id: k.id,
    name: k.name,
    keyPrefix: k.key_prefix,
    permissions: k.permissions,
    isActive: k.is_active,
    lastUsedAt: k.last_used_at?.toISOString() ?? null,
    expiresAt: k.expires_at?.toISOString() ?? null,
    createdAt: k.created_at.toISOString(),
  }));

  return apiSuccess(res, {
    data: keys,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}

// Get single API key
export async function getApiKey(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const keyResult = await pool.query<ApiKey>(
    'SELECT * FROM api_keys WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  const k = keyResult.rows[0];
  if (!k) {
    return apiError(res, 'API key not found', 404);
  }

  return apiSuccess(res, {
    id: k.id,
    name: k.name,
    keyPrefix: k.key_prefix,
    permissions: k.permissions,
    isActive: k.is_active,
    lastUsedAt: k.last_used_at?.toISOString() ?? null,
    expiresAt: k.expires_at?.toISOString() ?? null,
    createdAt: k.created_at.toISOString(),
    updatedAt: k.updated_at.toISOString(),
  });
}

// Create API key
export async function createApiKey(req: Request, res: Response) {
  const userId = req.user!.id;
  const { name, permissions, expiresAt } = req.body;

  if (!name || !permissions || !Array.isArray(permissions) || permissions.length === 0) {
    return apiError(res, 'Name and permissions are required', 400);
  }

  // Validate permissions
  const invalidPermissions = permissions.filter((p: string) => !AVAILABLE_PERMISSIONS.includes(p));
  if (invalidPermissions.length > 0) {
    return apiError(res, `Invalid permissions: ${invalidPermissions.join(', ')}`, 400);
  }

  // Generate API key - Format: ah_XXXXXX_YYYYYYYYYYYYYYYYYYYYYYYY
  const keyId = crypto.randomBytes(4).toString('hex');
  const secret = crypto.randomBytes(24).toString('hex');
  const fullKey = `ah_${keyId}_${secret}`;
  const keyPrefix = fullKey.substring(0, 10); // ah_XXXXXX

  // Hash the full key with argon2
  const keyHash = await argon2.hash(fullKey, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  const result = await pool.query<ApiKey>(
    `INSERT INTO api_keys (user_id, name, key_prefix, key_hash, permissions, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [
      userId,
      name,
      keyPrefix,
      keyHash,
      permissions,
      expiresAt ? new Date(expiresAt) : null,
    ]
  );

  const apiKey = result.rows[0];
  if (!apiKey) {
    return apiError(res, 'Failed to create API key', 500);
  }

  logger.info({ apiKeyId: apiKey.id, userId }, 'API key created');

  // Return the full key - this is the only time it will be shown
  return apiSuccess(res, {
    id: apiKey.id,
    name: apiKey.name,
    key: fullKey,
    keyPrefix: apiKey.key_prefix,
    permissions: apiKey.permissions,
    expiresAt: apiKey.expires_at?.toISOString() ?? null,
    createdAt: apiKey.created_at.toISOString(),
  }, 201);
}

// Update API key
export async function updateApiKey(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;
  const { name, permissions, isActive } = req.body;

  // Verify ownership
  const existingResult = await pool.query(
    'SELECT id FROM api_keys WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'API key not found', 404);
  }

  // Validate permissions if provided
  if (permissions) {
    const invalidPermissions = permissions.filter((p: string) => !AVAILABLE_PERMISSIONS.includes(p));
    if (invalidPermissions.length > 0) {
      return apiError(res, `Invalid permissions: ${invalidPermissions.join(', ')}`, 400);
    }
  }

  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (name !== undefined) {
    updates.push(`name = $${paramIndex++}`);
    values.push(name);
  }
  if (permissions !== undefined) {
    updates.push(`permissions = $${paramIndex++}`);
    values.push(permissions);
  }
  if (isActive !== undefined) {
    updates.push(`is_active = $${paramIndex++}`);
    values.push(isActive);
  }

  if (updates.length === 0) {
    return apiError(res, 'No fields to update', 400);
  }

  updates.push(`updated_at = NOW()`);
  values.push(id);

  const result = await pool.query<ApiKey>(
    `UPDATE api_keys SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
    values
  );

  const apiKey = result.rows[0];
  logger.info({ apiKeyId: id, userId }, 'API key updated');

  return apiSuccess(res, {
    id: apiKey!.id,
    name: apiKey!.name,
    permissions: apiKey!.permissions,
    isActive: apiKey!.is_active,
    updatedAt: apiKey!.updated_at.toISOString(),
  });
}

// Delete API key
export async function deleteApiKey(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  const existingResult = await pool.query(
    'SELECT id FROM api_keys WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'API key not found', 404);
  }

  await pool.query('DELETE FROM api_keys WHERE id = $1', [id]);

  logger.info({ apiKeyId: id, userId }, 'API key deleted');

  return apiSuccess(res, { message: 'API key deleted successfully' });
}

// Regenerate API key
export async function regenerateApiKey(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
  const userId = req.user!.id;

  // Verify ownership
  const existingResult = await pool.query<ApiKey>(
    'SELECT * FROM api_keys WHERE id = $1 AND user_id = $2',
    [id, userId]
  );

  if (existingResult.rows.length === 0) {
    return apiError(res, 'API key not found', 404);
  }

  // Generate new key
  const keyId = crypto.randomBytes(4).toString('hex');
  const secret = crypto.randomBytes(24).toString('hex');
  const fullKey = `ah_${keyId}_${secret}`;
  const keyPrefix = fullKey.substring(0, 10);

  const keyHash = await argon2.hash(fullKey, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  const result = await pool.query<ApiKey>(
    `UPDATE api_keys
     SET key_prefix = $1, key_hash = $2, updated_at = NOW()
     WHERE id = $3
     RETURNING *`,
    [keyPrefix, keyHash, id]
  );

  const apiKey = result.rows[0];

  logger.info({ apiKeyId: id, userId }, 'API key regenerated');

  return apiSuccess(res, {
    id: apiKey!.id,
    name: apiKey!.name,
    key: fullKey,
    keyPrefix: apiKey!.key_prefix,
    permissions: apiKey!.permissions,
    updatedAt: apiKey!.updated_at.toISOString(),
  });
}
