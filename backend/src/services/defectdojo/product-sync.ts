import { db } from '../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../utils/logger.js';
import { getDefectDojoClient } from './client.js';

const logger = createLogger('defectdojo-sync');

/**
 * Sync a project to DefectDojo as a product.
 * Creates the DD product if it doesn't exist, stores the product_id.
 */
export async function syncProjectToDefectDojo(
  projectId: string,
  projectName: string,
  description?: string
): Promise<number | null> {
  const client = getDefectDojoClient();
  if (!client.isEnabled()) return null;

  // Check if project already has a DD product ID
  const existing = await db.execute(sql`
    SELECT defectdojo_product_id FROM projects WHERE id = ${projectId}
  `);

  const row = existing.rows[0] as Record<string, unknown> | undefined;
  if (row?.defectdojo_product_id) {
    return row.defectdojo_product_id as number;
  }

  // Create new product in DefectDojo
  const product = await client.createProduct(
    projectName,
    description || `Code Hardener project: ${projectName}`
  );

  if (!product) {
    logger.warn({ projectId }, 'Failed to create DefectDojo product');
    return null;
  }

  // Store the product ID
  await db.execute(sql`
    UPDATE projects SET defectdojo_product_id = ${product.id} WHERE id = ${projectId}
  `);

  logger.info({ projectId, productId: product.id }, 'Project synced to DefectDojo');
  return product.id;
}

/**
 * Get the DefectDojo product ID for a project, creating if needed.
 */
export async function ensureDefectDojoProduct(
  projectId: string
): Promise<number | null> {
  const client = getDefectDojoClient();
  if (!client.isEnabled()) return null;

  const result = await db.execute(sql`
    SELECT defectdojo_product_id, name, description FROM projects WHERE id = ${projectId}
  `);

  const row = result.rows[0] as Record<string, unknown> | undefined;
  if (!row) return null;

  if (row.defectdojo_product_id) {
    return row.defectdojo_product_id as number;
  }

  return syncProjectToDefectDojo(
    projectId,
    row.name as string,
    row.description as string | undefined
  );
}
