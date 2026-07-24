/**
 * OAuth Audit Logger (security-m005)
 *
 * Implements comprehensive audit logging for all OAuth token operations:
 * - Token creation (OAuth flow completion)
 * - Token refresh events
 * - Token revocation (user-initiated and system-initiated)
 * - Failed token validation attempts
 * - Scope changes
 *
 * Each log entry includes: user_id, timestamp, IP address, user_agent,
 * operation_type, and result. Logs are persisted to the database for
 * compliance (90-day retention minimum) and emitted via structured logging.
 *
 * SEC-026, SEC-026-A, SEC-026-B
 */

import { Request } from 'express';
import { db, pool } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('oauth-audit');

// ============================================================================
// Types
// ============================================================================

export type OAuthAuditEventType =
  | 'token_created'
  | 'token_refreshed'
  | 'token_revoked'
  | 'token_validation_failed'
  | 'scope_changed'
  | 'connection_expired';

export type OAuthAuditResult = 'success' | 'failure';

export interface OAuthAuditEvent {
  eventType: OAuthAuditEventType;
  userId: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  result: OAuthAuditResult;
  details?: OAuthAuditDetails;
}

export interface OAuthAuditDetails {
  scopes?: string[];
  previousScopes?: string[];
  reason?: string;
  githubUserId?: number;
  githubUsername?: string;
  connectionId?: string;
  errorMessage?: string;
  revokedBy?: 'user' | 'system' | 'admin';
}

export interface OAuthAuditLogRow {
  [key: string]: unknown;
  id: string;
  event_type: string;
  user_id: string;
  timestamp: Date;
  ip_address: string;
  user_agent: string;
  result: string;
  details: OAuthAuditDetails | null;
  created_at: Date;
}

export interface OAuthAuditQueryOptions {
  userId?: string;
  eventType?: OAuthAuditEventType;
  result?: OAuthAuditResult;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract client IP from request, handling proxies
 */
function extractIpAddress(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Extract user agent from request
 */
function extractUserAgent(req: Request): string {
  return req.headers['user-agent'] || 'unknown';
}

// ============================================================================
// OAuth Audit Logger
// ============================================================================

export class OAuthAuditLogger {
  /**
   * Log a token creation event (OAuth flow completion)
   */
  async logTokenCreated(
    userId: string,
    req: Request,
    details: {
      scopes: string[];
      githubUserId?: number;
      githubUsername?: string;
      connectionId: string;
    }
  ): Promise<void> {
    await this.log({
      eventType: 'token_created',
      userId,
      timestamp: new Date(),
      ipAddress: extractIpAddress(req),
      userAgent: extractUserAgent(req),
      result: 'success',
      details: {
        scopes: details.scopes,
        githubUserId: details.githubUserId,
        githubUsername: details.githubUsername,
        connectionId: details.connectionId,
      },
    });
  }

  /**
   * Log a token refresh event
   */
  async logTokenRefreshed(
    userId: string,
    req: Request,
    details: {
      connectionId: string;
      scopes?: string[];
    }
  ): Promise<void> {
    await this.log({
      eventType: 'token_refreshed',
      userId,
      timestamp: new Date(),
      ipAddress: extractIpAddress(req),
      userAgent: extractUserAgent(req),
      result: 'success',
      details: {
        connectionId: details.connectionId,
        scopes: details.scopes,
      },
    });
  }

  /**
   * Log a token revocation event
   */
  async logTokenRevoked(
    userId: string,
    req: Request,
    details: {
      connectionId: string;
      reason: string;
      revokedBy: 'user' | 'system' | 'admin';
    }
  ): Promise<void> {
    await this.log({
      eventType: 'token_revoked',
      userId,
      timestamp: new Date(),
      ipAddress: extractIpAddress(req),
      userAgent: extractUserAgent(req),
      result: 'success',
      details: {
        connectionId: details.connectionId,
        reason: details.reason,
        revokedBy: details.revokedBy,
      },
    });
  }

  /**
   * Log a failed token validation attempt
   */
  async logValidationFailed(
    userId: string,
    req: Request,
    details: {
      connectionId?: string;
      reason: string;
      errorMessage?: string;
    }
  ): Promise<void> {
    await this.log({
      eventType: 'token_validation_failed',
      userId,
      timestamp: new Date(),
      ipAddress: extractIpAddress(req),
      userAgent: extractUserAgent(req),
      result: 'failure',
      details: {
        connectionId: details.connectionId,
        reason: details.reason,
        errorMessage: details.errorMessage,
      },
    });
  }

  /**
   * Log a scope change event
   */
  async logScopeChanged(
    userId: string,
    req: Request,
    details: {
      connectionId: string;
      previousScopes: string[];
      newScopes: string[];
    }
  ): Promise<void> {
    await this.log({
      eventType: 'scope_changed',
      userId,
      timestamp: new Date(),
      ipAddress: extractIpAddress(req),
      userAgent: extractUserAgent(req),
      result: 'success',
      details: {
        connectionId: details.connectionId,
        previousScopes: details.previousScopes,
        scopes: details.newScopes,
      },
    });
  }

  /**
   * Log a connection expiration event (system-initiated)
   */
  async logConnectionExpired(
    userId: string,
    details: {
      connectionId: string;
      reason: string;
    }
  ): Promise<void> {
    await this.log({
      eventType: 'connection_expired',
      userId,
      timestamp: new Date(),
      ipAddress: 'system',
      userAgent: 'system',
      result: 'success',
      details: {
        connectionId: details.connectionId,
        reason: details.reason,
        revokedBy: 'system',
      },
    });
  }

  /**
   * Query audit logs with filtering
   */
  async queryLogs(options: OAuthAuditQueryOptions): Promise<{
    logs: OAuthAuditEvent[];
    total: number;
  }> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (options.userId) {
      conditions.push(`user_id = $${paramIndex++}`);
      params.push(options.userId);
    }

    if (options.eventType) {
      conditions.push(`event_type = $${paramIndex++}`);
      params.push(options.eventType);
    }

    if (options.result) {
      conditions.push(`result = $${paramIndex++}`);
      params.push(options.result);
    }

    if (options.startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(options.startDate);
    }

    if (options.endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(options.endDate);
    }

    const whereClause = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const limit = options.limit || 50;
    const offset = options.offset || 0;

    // Count total matching records
    const countResult = await pool.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM oauth_audit_log ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0]?.count || '0', 10);

    // Fetch records
    const logsResult = await pool.query<OAuthAuditLogRow>(
      `SELECT * FROM oauth_audit_log ${whereClause} ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      [...params, limit, offset]
    );

    const logs = logsResult.rows.map((row) => this.rowToEvent(row));

    return { logs, total };
  }

  /**
   * Cleanup old audit logs (retain for at least 90 days per SEC-026-A)
   * Only deletes logs older than the specified retention period.
   */
  async cleanupOldLogs(retentionDays: number = 90): Promise<number> {
    if (retentionDays < 90) {
      logger.warn(
        { requestedDays: retentionDays },
        'OAuth audit log retention must be at least 90 days per SEC-026-A. Using 90 days.'
      );
      retentionDays = 90;
    }

    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

    const result = await db.execute<{ count: string }>(sql`
      WITH deleted AS (
        DELETE FROM oauth_audit_log
        WHERE timestamp < ${cutoff}
        RETURNING *
      )
      SELECT COUNT(*) as count FROM deleted
    `);

    const deletedCount = parseInt(result.rows[0]?.count || '0', 10);

    if (deletedCount > 0) {
      logger.info(
        { deletedCount, cutoff: cutoff.toISOString(), retentionDays },
        'OAuth audit logs cleaned up'
      );
    }

    return deletedCount;
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  /**
   * Core logging method -- writes to both structured logs and database
   */
  private async log(event: OAuthAuditEvent): Promise<void> {
    // Structured log for real-time monitoring
    const logData = {
      eventType: event.eventType,
      userId: event.userId,
      ipAddress: event.ipAddress,
      result: event.result,
      ...event.details,
    };

    if (event.result === 'failure') {
      logger.warn(logData, `OAuth audit: ${event.eventType}`);
    } else {
      logger.info(logData, `OAuth audit: ${event.eventType}`);
    }

    // Persist to database for compliance
    try {
      await db.execute(sql`
        INSERT INTO oauth_audit_log (
          event_type, user_id, timestamp, ip_address, user_agent, result, details
        ) VALUES (
          ${event.eventType},
          ${event.userId},
          ${event.timestamp},
          ${event.ipAddress},
          ${event.userAgent},
          ${event.result},
          ${JSON.stringify(event.details || null)}::jsonb
        )
      `);
    } catch (error) {
      // Log persistence failures but don't throw -- audit logging should
      // not break the primary operation
      logger.error(
        { error, eventType: event.eventType, userId: event.userId },
        'Failed to persist OAuth audit log to database'
      );
    }
  }

  /**
   * Convert database row to OAuthAuditEvent
   */
  private rowToEvent(row: OAuthAuditLogRow): OAuthAuditEvent {
    return {
      eventType: row.event_type as OAuthAuditEventType,
      userId: row.user_id,
      timestamp: row.timestamp,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      result: row.result as OAuthAuditResult,
      details: row.details || undefined,
    };
  }
}

// ============================================================================
// Singleton
// ============================================================================

let oauthAuditLoggerInstance: OAuthAuditLogger | null = null;

/**
 * Get the singleton OAuthAuditLogger instance
 */
export function getOAuthAuditLogger(): OAuthAuditLogger {
  if (!oauthAuditLoggerInstance) {
    oauthAuditLoggerInstance = new OAuthAuditLogger();
  }
  return oauthAuditLoggerInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetOAuthAuditLogger(): void {
  oauthAuditLoggerInstance = null;
}
