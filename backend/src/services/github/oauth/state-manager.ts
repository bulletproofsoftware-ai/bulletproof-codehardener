/**
 * OAuth State Manager (GH-002)
 *
 * Manages cryptographic state tokens for OAuth CSRF protection.
 * - 32-byte cryptographically random state tokens
 * - 10-minute expiration
 * - Single-use verification
 * - Redis storage for distributed deployments
 */

import crypto from 'crypto';
import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import type { OAuthState, OAuthStateRow } from '../../../types/github.types.js';

export interface StateManagerConfig {
  expirationMinutes?: number;
  stateLength?: number;
}

export class OAuthStateManager {
  private readonly STATE_LENGTH: number;
  private readonly EXPIRATION_MS: number;

  constructor(config: StateManagerConfig = {}) {
    this.STATE_LENGTH = config.stateLength || 32;
    this.EXPIRATION_MS = (config.expirationMinutes || 10) * 60 * 1000;
  }

  /**
   * Generate a cryptographically secure state token
   */
  private generateStateToken(): string {
    return crypto.randomBytes(this.STATE_LENGTH).toString('hex');
  }

  /**
   * Create a new OAuth state for a user
   */
  async createState(userId: string, redirectUri?: string): Promise<OAuthState> {
    const id = crypto.randomUUID();
    const stateToken = this.generateStateToken();
    const expiresAt = new Date(Date.now() + this.EXPIRATION_MS);

    await db.execute(sql`
      INSERT INTO github_oauth_states (
        id, user_id, state_token, redirect_uri, expires_at, used, created_at
      ) VALUES (
        ${id}, ${userId}, ${stateToken}, ${redirectUri || null}, ${expiresAt}, false, NOW()
      )
    `);

    return {
      id,
      userId,
      stateToken,
      redirectUri,
      expiresAt,
      used: false,
      createdAt: new Date(),
    };
  }

  /**
   * Verify and consume a state token
   * Returns the state if valid, null otherwise
   */
  async verifyAndConsumeState(stateToken: string, userId: string): Promise<OAuthState | null> {
    // Start transaction to ensure atomic verification and consumption
    const result = await db.execute<OAuthStateRow>(sql`
      UPDATE github_oauth_states
      SET used = true
      WHERE state_token = ${stateToken}
        AND user_id = ${userId}
        AND used = false
        AND expires_at > NOW()
      RETURNING *
    `);

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    return this.rowToState(row);
  }

  /**
   * Get a state by token without consuming it (for validation checks)
   */
  async getState(stateToken: string): Promise<OAuthState | null> {
    const result = await db.execute<OAuthStateRow>(sql`
      SELECT * FROM github_oauth_states
      WHERE state_token = ${stateToken}
        AND expires_at > NOW()
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return null;
    }

    return this.rowToState(result.rows[0]);
  }

  /**
   * Check if a state is valid (exists, not expired, not used)
   */
  async isStateValid(stateToken: string, userId: string): Promise<boolean> {
    const result = await db.execute<{ count: string }>(sql`
      SELECT COUNT(*) as count FROM github_oauth_states
      WHERE state_token = ${stateToken}
        AND user_id = ${userId}
        AND used = false
        AND expires_at > NOW()
    `);

    return parseInt(result.rows[0].count, 10) > 0;
  }

  /**
   * Clean up expired states
   */
  async cleanupExpiredStates(): Promise<number> {
    const result = await db.execute<{ count: string }>(sql`
      WITH deleted AS (
        DELETE FROM github_oauth_states
        WHERE expires_at < NOW()
        RETURNING *
      )
      SELECT COUNT(*) as count FROM deleted
    `);

    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Delete all states for a user (e.g., on logout or account deletion)
   */
  async deleteUserStates(userId: string): Promise<number> {
    const result = await db.execute<{ count: string }>(sql`
      WITH deleted AS (
        DELETE FROM github_oauth_states
        WHERE user_id = ${userId}
        RETURNING *
      )
      SELECT COUNT(*) as count FROM deleted
    `);

    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Get the count of recent state creations for rate limiting checks
   */
  async getRecentStateCount(userId: string, windowMinutes: number = 5): Promise<number> {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

    const result = await db.execute<{ count: string }>(sql`
      SELECT COUNT(*) as count FROM github_oauth_states
      WHERE user_id = ${userId}
        AND created_at > ${windowStart}
    `);

    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Convert database row to OAuthState object
   */
  private rowToState(row: OAuthStateRow): OAuthState {
    return {
      id: row.id,
      userId: row.user_id,
      stateToken: row.state_token,
      redirectUri: row.redirect_uri || undefined,
      expiresAt: new Date(row.expires_at),
      used: row.used,
      createdAt: new Date(row.created_at),
    };
  }
}

// Singleton instance
let stateManagerInstance: OAuthStateManager | null = null;

/**
 * Get the singleton OAuthStateManager instance
 */
export function getOAuthStateManager(): OAuthStateManager {
  if (!stateManagerInstance) {
    stateManagerInstance = new OAuthStateManager();
  }
  return stateManagerInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetOAuthStateManager(): void {
  stateManagerInstance = null;
}
