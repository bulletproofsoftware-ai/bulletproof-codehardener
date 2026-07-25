import type { Request, Response, NextFunction } from 'express';
import { verifyToken, getUserById, type UserData } from '../services/auth.service.js';
import { sendUnauthorized, sendForbidden } from '../utils/apiResponse.js';
import { db, pool } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../utils/logger.js';
import { isDev } from '../config/env.js';

const logger = createLogger('auth-middleware');

/** Row shape for dev auth user lookup/creation */
interface DevUserRow {
  id: string;
  email: string;
  name: string;
  createdAt: Date;
}

/** Row shape for API key lookup */
interface ApiKeyLookupRow {
  id: string;
  user_id: string;
  scopes: string[];
  key_hash: string;
  expires_at: string | null;
}

declare global {
  namespace Express {
    interface Request {
      user?: UserData;
      apiKey?: { id: string; userId: string; scopes: string[] };
      withRLS?: <T>(callback: (tx: any) => Promise<T>) => Promise<T>;
    }
  }
}

// JWT Bearer token authentication
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Development mode: Allow X-User-Id header for testing
    if (isDev) {
      const devUserId = req.headers['x-user-id'] as string;
      if (devUserId) {
        // Create or get test user on-the-fly using email-based lookup
        const testEmail = devUserId.includes('@') ? devUserId : `${devUserId}@test.local`;

        // First try to find existing user by email
        const existing = await db.execute(
          sql`SELECT id, email, name, created_at as "createdAt"
              FROM users WHERE email = ${testEmail}`
        );

        let user: UserData;
        if (existing.rows.length > 0) {
          const row = existing.rows[0] as unknown as DevUserRow;
          user = {
            id: row.id,
            email: row.email,
            name: row.name,
            createdAt: row.createdAt,
          };
        } else {
          // Create new test user with auto-generated UUID
          const result = await db.execute(
            sql`INSERT INTO users (email, name, email_verified)
                VALUES (${testEmail}, 'Test User', true)
                RETURNING id, email, name, created_at as "createdAt"`
          );
          const row = result.rows[0] as unknown as DevUserRow;
          user = {
            id: row.id,
            email: row.email,
            name: row.name,
            createdAt: row.createdAt,
          };
        }

        req.user = user;
        logger.debug({ userId: user.id, devHeader: devUserId }, 'Dev auth bypass with X-User-Id');
        next();
        return;
      }
    }

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      sendUnauthorized(res, 'Authorization header required');
      return;
    }

    // Check for Bearer token
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const payload = verifyToken(token);

      if (payload.type !== 'access') {
        sendUnauthorized(res, 'Invalid token type');
        return;
      }

      const user = await getUserById(payload.userId);
      if (!user) {
        sendUnauthorized(res, 'User not found');
        return;
      }

      req.user = user;
      next();
      return;
    }

    // Check for API key
    if (authHeader.startsWith('ApiKey ')) {
      const apiKey = authHeader.slice(7);
      const keyPrefix = apiKey.slice(0, 8);

      // A key prefix is only the first 8 characters and is NOT unique, so
      // this can legitimately return several rows. The previous code checked
      // rows[0] alone, which meant a valid key was rejected whenever another
      // key happened to share its prefix.
      //
      // is_active is also filtered here: it was never consulted, so a revoked
      // key continued to authenticate for as long as it had not expired.
      const result = await db.execute(
        sql`SELECT ak.id, ak.user_id, ak.scopes, ak.key_hash, ak.expires_at
            FROM api_keys ak
            WHERE ak.key_prefix = ${keyPrefix}
            AND ak.is_active = true
            AND (ak.expires_at IS NULL OR ak.expires_at > NOW())`
      );

      if (result.rows.length === 0) {
        sendUnauthorized(res, 'Invalid API key');
        return;
      }

      const bcrypt = await import('bcryptjs');
      let keyData: ApiKeyLookupRow | null = null;
      for (const row of result.rows) {
        const candidate = row as unknown as ApiKeyLookupRow;
        // bcrypt.compare is constant-time for a given hash; every candidate
        // sharing this prefix is checked so a collision cannot mask a match.
        if (await bcrypt.compare(apiKey, candidate.key_hash)) {
          keyData = candidate;
          break;
        }
      }

      if (!keyData) {
        sendUnauthorized(res, 'Invalid API key');
        return;
      }

      // Update last used
      await db.execute(
        sql`UPDATE api_keys SET last_used_at = NOW() WHERE id = ${keyData.id}`
      );

      const user = await getUserById(keyData.user_id);
      if (!user) {
        sendUnauthorized(res, 'User not found');
        return;
      }

      req.user = user;
      req.apiKey = {
        id: keyData.id,
        userId: keyData.user_id,
        scopes: keyData.scopes || [],
      };

      next();
      return;
    }

    sendUnauthorized(res, 'Invalid authorization format');
  } catch (error) {
    logger.error({ error }, 'Authentication error');
    sendUnauthorized(res, 'Authentication failed');
  }
};

/**
 * Middleware to expose RLS-scoped database access via req.withRLS().
 * Can be mounted at the app level — uses req.user lazily at call time.
 *
 * Usage in route handlers (after authenticate):
 *   const result = await req.withRLS(async (tx) => {
 *     return tx.execute(sql`SELECT * FROM projects`);
 *   });
 *
 * The callback runs in a transaction with SET LOCAL app.user_id,
 * so all queries within it are filtered by RLS policies.
 */
export const attachRLS = (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  req.withRLS = async <T>(callback: (tx: any) => Promise<T>): Promise<T> => {
    const userId = req.user?.id;
    if (!userId) {
      throw new Error('withRLS requires authenticated user');
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT set_config($1, $2, true)', ['app.user_id', userId]);
      const { drizzle: createDrizzle } = await import('drizzle-orm/node-postgres');
      const txDb = createDrizzle(client as any);
      const result = await callback(txDb);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  };
  next();
};

// Optional authentication - continues even without auth
export const optionalAuth = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      next();
      return;
    }

    const token = authHeader.slice(7);
    const payload = verifyToken(token);

    if (payload.type === 'access') {
      const user = await getUserById(payload.userId);
      if (user) {
        req.user = user;
      }
    }

    next();
  } catch {
    // Continue without auth on error
    next();
  }
};

// Check for specific API key scope
export const requireScope = (scope: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.apiKey) {
      // JWT auth doesn't have scopes, allow all
      next();
      return;
    }

    if (!req.apiKey.scopes.includes(scope) && !req.apiKey.scopes.includes('*')) {
      sendForbidden(res, `Missing required scope: ${scope}`);
      return;
    }

    next();
  };
};

// Require specific user ID or admin
export const requireOwnership = (userIdParam: string = 'userId') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendUnauthorized(res);
      return;
    }

    const targetUserId = req.params[userIdParam];
    if (targetUserId && targetUserId !== req.user.id) {
      sendForbidden(res, 'Access denied');
      return;
    }

    next();
  };
};
