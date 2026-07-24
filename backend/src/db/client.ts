import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool, type PoolClient } from 'pg';
import { databaseUrl, isDev } from '../config/env.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('database');

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: databaseUrl,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Handle pool errors
pool.on('error', (err) => {
  logger.error({ err }, 'Unexpected error on idle database client');
});

pool.on('connect', () => {
  if (isDev) {
    logger.debug('New database client connected');
  }
});

// Create Drizzle ORM instance
export const db = drizzle(pool);

// Export pool for direct access when needed
export { pool };

/**
 * Execute a callback within a transaction that has RLS context set.
 * OPT-IN: Row-Level Security for multi-tenant isolation.
 * Requires postgres/migrations/010b_row_level_security.sql to be applied
 * and the codehardener_app role to be created. Not active in dev mode.
 *
 * Acquires a dedicated connection, sets app.user_id, runs the callback,
 * then commits and releases. This ensures all queries in the callback
 * use the same connection with the correct tenant context.
 */
export async function withRLS<T>(
  userId: string,
  callback: (tx: NodePgDatabase) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1, $2, true)', ['app.user_id', userId]);
    const txDb = drizzle(client as any);
    const result = await callback(txDb);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Set RLS context on a dedicated pool client.
 * Caller is responsible for releasing the client.
 */
export async function setRLSContext(userId: string): Promise<PoolClient> {
  const client = await pool.connect();
  await client.query('SELECT set_config($1, $2, false)', ['app.user_id', userId]);
  return client;
}

// Health check function
export async function checkDbConnection(): Promise<boolean> {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    return true;
  } catch (error) {
    logger.error({ error }, 'Database connection check failed');
    return false;
  }
}

// Graceful shutdown
export async function closeDbConnection(): Promise<void> {
  try {
    await pool.end();
    logger.info('Database connection pool closed');
  } catch (error) {
    logger.error({ error }, 'Error closing database connection pool');
    throw error;
  }
}
