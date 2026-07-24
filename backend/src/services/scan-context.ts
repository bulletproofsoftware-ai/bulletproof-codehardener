import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../utils/logger.js';
import { decryptCredential, decryptAuthConfig, type StoredAuthConfig } from './crypto/credential-encryption.js';
import type { ScanJobData } from './queue/scan.queue.js';

const logger = createLogger('scan-context');

/**
 * Fetch project DAST context and decrypt credentials for scan execution.
 * Returns fields to merge into ScanJobData.
 */
export async function buildScanContext(
  projectId: string,
  overrides?: { targetUrl?: string; containerImage?: string; openapiSpecPath?: string },
) {
  const result = await db.execute(sql`
    SELECT p.target_url, p.container_image, p.openapi_spec_path, p.auth_config,
           p.registry_credentials_id,
           rc.registry, rc.username, rc.password_encrypted, rc.password_iv, rc.password_tag
    FROM projects p
    LEFT JOIN registry_credentials rc ON rc.id = p.registry_credentials_id
    WHERE p.id = ${projectId}
  `);

  if (result.rows.length === 0) return {};

  const row = result.rows[0] as Record<string, unknown>;

  // Per-scan overrides take precedence
  const targetUrl = overrides?.targetUrl || (row.target_url as string | null) || undefined;
  const containerImage = overrides?.containerImage || (row.container_image as string | null) || undefined;
  const openapiSpecPath = overrides?.openapiSpecPath || (row.openapi_spec_path as string | null) || undefined;

  // Decrypt auth config password if present
  let authConfig: ScanJobData['authConfig'];
  if (row.auth_config) {
    try {
      const stored = row.auth_config as StoredAuthConfig;
      const decrypted = decryptAuthConfig(stored);
      authConfig = decrypted;
    } catch (err) {
      logger.warn({ projectId, error: (err as Error).message }, 'Failed to decrypt auth config');
    }
  }

  // Decrypt registry credentials if present
  let registryCredentials: ScanJobData['registryCredentials'];
  if (row.password_encrypted && row.password_iv && row.password_tag) {
    try {
      registryCredentials = {
        registry: row.registry as string,
        username: row.username as string,
        password: decryptCredential(
          row.password_encrypted as string,
          row.password_iv as string,
          row.password_tag as string,
        ),
      };
    } catch (err) {
      logger.warn({ projectId, error: (err as Error).message }, 'Failed to decrypt registry credentials');
    }
  }

  return { targetUrl, containerImage, openapiSpecPath, authConfig, registryCredentials };
}
