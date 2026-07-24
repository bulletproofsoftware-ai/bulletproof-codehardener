import type { Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendSuccess, sendCreated, sendValidationError, sendNoContent } from '../utils/apiResponse.js';
import { NotFoundError } from '../middleware/errorHandler.js';
import { createLogger } from '../utils/logger.js';
import { encryptCredential } from '../services/crypto/credential-encryption.js';

const logger = createLogger('registry-credentials-controller');

const createCredentialSchema = z.object({
  registry: z.string().min(1).max(255),
  username: z.string().min(1).max(255),
  password: z.string().min(1),
});

export async function createRegistryCredential(req: Request, res: Response) {
  const validation = createCredentialSchema.safeParse(req.body);
  if (!validation.success) {
    return sendValidationError(res, validation.error.errors);
  }

  const { registry, username, password } = validation.data;
  const { encrypted, iv, tag } = encryptCredential(password);

  const result = await db.execute(sql`
    INSERT INTO registry_credentials (user_id, registry, username, password_encrypted, password_iv, password_tag)
    VALUES (${req.user!.id}, ${registry}, ${username}, ${encrypted}, ${iv}, ${tag})
    RETURNING id, registry, username, created_at, updated_at
  `);

  const row = result.rows[0] as Record<string, unknown>;
  logger.info({ credentialId: row.id, registry }, 'Registry credential created');

  return sendCreated(res, {
    id: row.id,
    registry: row.registry,
    username: row.username,
    password: '********',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  });
}

export async function listRegistryCredentials(req: Request, res: Response) {
  const result = await db.execute(sql`
    SELECT id, registry, username, created_at, updated_at
    FROM registry_credentials
    WHERE user_id = ${req.user!.id}
    ORDER BY created_at DESC
  `);

  const credentials = result.rows.map((row: Record<string, unknown>) => ({
    id: row.id,
    registry: row.registry,
    username: row.username,
    password: '********',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));

  return sendSuccess(res, credentials);
}

export async function deleteRegistryCredential(req: Request, res: Response) {
  const { id } = z.object({ id: z.string().uuid() }).parse(req.params);

  // Delete only if owned by the current user
  const result = await db.execute(sql`
    DELETE FROM registry_credentials
    WHERE id = ${id} AND user_id = ${req.user!.id}
    RETURNING id
  `);

  if (result.rows.length === 0) {
    throw new NotFoundError('Registry credential not found');
  }

  // Unlink any projects that referenced this credential
  await db.execute(sql`
    UPDATE projects
    SET registry_credentials_id = NULL, updated_at = NOW()
    WHERE registry_credentials_id = ${id} AND user_id = ${req.user!.id}
  `);

  logger.info({ credentialId: id }, 'Registry credential deleted');

  return sendNoContent(res);
}
