/**
 * GitHub Webhook Service (GH-021 to GH-023, security-h002)
 *
 * Manages GitHub webhooks:
 * - Webhook creation and management
 * - Event processing with replay prevention
 * - Scan triggering based on events
 */

import crypto from 'crypto';
import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import Redis from 'ioredis';
import { getGitHubOAuthService } from '../oauth/github-oauth.service.js';
import { getTokenEncryption } from '../oauth/token-encryption.js';
import { getWebhookSignatureValidator } from './signature-validator.js';
import { logger } from '../../../utils/logger.js';
import { redisUrl } from '../../../config/env.js';
import type {
  WebhookPayload,
  WebhookEvent,
  WebhookEventRow,
  WebhookConfig,
  DeliveryCheckResult,
  ConnectedRepositoryRow,
} from '../../../types/github.types.js';

const GITHUB_API_URL = 'https://api.github.com';
const DELIVERY_ID_TTL = 24 * 60 * 60; // 24 hours in seconds
const DELIVERY_ID_PREFIX = 'gh:webhook:delivery:';

// Supported webhook events
const SUPPORTED_EVENTS = ['push', 'pull_request', 'create', 'delete'];

export class GitHubWebhookService {
  private redis: Redis | null = null;

  constructor() {
    this.initRedis();
  }

  private initRedis(): void {
    try {
      if (redisUrl) {
        this.redis = new Redis(redisUrl);
        this.redis.on('error', (err) => {
          logger.error({ error: err }, 'Redis connection error in webhook service');
        });
      }
    } catch (error) {
      logger.warn({ error }, 'Redis not available for webhook deduplication');
    }
  }

  /**
   * Create a webhook for a repository
   */
  async createWebhook(
    repositoryId: string,
    userId: string,
    webhookUrl: string
  ): Promise<{ webhookId: number; secret: string }> {
    // Get repository details
    const repoResult = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE id = ${repositoryId} AND user_id = ${userId}
      LIMIT 1
    `);

    if (repoResult.rows.length === 0) {
      throw new Error('Repository not found');
    }

    const repo = repoResult.rows[0];

    // Get access token
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(repo.connection_id, userId);

    if (!accessToken) {
      throw new Error('GitHub access token not available');
    }

    // Generate webhook secret
    const secret = crypto.randomBytes(32).toString('hex');

    // Create webhook via GitHub API
    const response = await fetch(
      `${GITHUB_API_URL}/repos/${repo.owner}/${repo.name}/hooks`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'web',
          active: true,
          events: SUPPORTED_EVENTS,
          config: {
            url: webhookUrl,
            content_type: 'json',
            secret,
            insecure_ssl: '0',
          },
        }),
      }
    );

    if (!response.ok) {
      const errorData = await response.json() as { message?: string };
      throw new Error(`Failed to create webhook: ${errorData.message || response.status}`);
    }

    const webhookData = await response.json() as { id: number };

    // Encrypt and store webhook secret
    const encryption = getTokenEncryption();
    const encryptedSecret = encryption.encrypt(secret);

    // Update repository with webhook info
    await db.execute(sql`
      UPDATE github_repositories
      SET
        webhook_id = ${webhookData.id},
        webhook_secret_encrypted = ${encryptedSecret.ciphertext},
        webhook_secret_iv = ${encryptedSecret.iv},
        webhook_secret_tag = ${encryptedSecret.tag},
        webhook_active = true,
        updated_at = NOW()
      WHERE id = ${repositoryId}
    `);

    logger.info({
      repositoryId,
      webhookId: webhookData.id,
      owner: repo.owner,
      name: repo.name,
    }, 'Webhook created');

    return {
      webhookId: webhookData.id,
      secret,
    };
  }

  /**
   * Delete a webhook
   */
  async deleteWebhook(repositoryId: string, userId: string): Promise<void> {
    // Get repository details
    const repoResult = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE id = ${repositoryId} AND user_id = ${userId}
      LIMIT 1
    `);

    if (repoResult.rows.length === 0) {
      throw new Error('Repository not found');
    }

    const repo = repoResult.rows[0];

    if (!repo.webhook_id) {
      return; // No webhook to delete
    }

    // Get access token
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(repo.connection_id, userId);

    if (!accessToken) {
      throw new Error('GitHub access token not available');
    }

    // Delete webhook via GitHub API
    const response = await fetch(
      `${GITHUB_API_URL}/repos/${repo.owner}/${repo.name}/hooks/${repo.webhook_id}`,
      {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      }
    );

    if (!response.ok && response.status !== 404) {
      throw new Error(`Failed to delete webhook: ${response.status}`);
    }

    // Clear webhook info from repository
    await db.execute(sql`
      UPDATE github_repositories
      SET
        webhook_id = NULL,
        webhook_secret_encrypted = NULL,
        webhook_secret_iv = NULL,
        webhook_secret_tag = NULL,
        webhook_active = false,
        updated_at = NOW()
      WHERE id = ${repositoryId}
    `);

    logger.info({
      repositoryId,
      webhookId: repo.webhook_id,
    }, 'Webhook deleted');
  }

  /**
   * Check if a delivery ID has been seen before (replay prevention)
   */
  async checkDeliveryId(deliveryId: string): Promise<DeliveryCheckResult> {
    if (!this.redis) {
      // Without Redis, always allow (but log warning)
      logger.warn('Redis not available - webhook replay prevention disabled');
      return { isDuplicate: false };
    }

    const key = `${DELIVERY_ID_PREFIX}${deliveryId}`;

    try {
      // Try to set the key with NX (only if not exists)
      const result = await this.redis.set(key, Date.now().toString(), 'EX', DELIVERY_ID_TTL, 'NX');

      if (result === null) {
        // Key already exists - this is a duplicate
        const firstSeen = await this.redis.get(key);
        return {
          isDuplicate: true,
          firstSeenAt: firstSeen ? new Date(parseInt(firstSeen, 10)) : undefined,
        };
      }

      return { isDuplicate: false };
    } catch (error) {
      logger.error({ error, deliveryId }, 'Redis error during delivery check');
      // On error, allow the request but log
      return { isDuplicate: false };
    }
  }

  /**
   * Process a webhook event
   */
  async processWebhookEvent(
    eventType: string,
    deliveryId: string,
    signature: string,
    payload: WebhookPayload,
    rawPayload: string
  ): Promise<WebhookEvent> {
    // Check for replay
    const deliveryCheck = await this.checkDeliveryId(deliveryId);
    if (deliveryCheck.isDuplicate) {
      logger.warn({
        deliveryId,
        firstSeenAt: deliveryCheck.firstSeenAt,
      }, 'Duplicate webhook delivery rejected');
      throw new Error('Duplicate webhook delivery');
    }

    // Find repository by GitHub repo ID
    const repoResult = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE github_repo_id = ${payload.repository.id}
      LIMIT 1
    `);

    if (repoResult.rows.length === 0) {
      throw new Error('Repository not found');
    }

    const repo = repoResult.rows[0];

    // Validate signature
    if (repo.webhook_secret_encrypted && repo.webhook_secret_iv && repo.webhook_secret_tag) {
      const encryption = getTokenEncryption();
      const secret = encryption.decrypt({
        ciphertext: repo.webhook_secret_encrypted,
        iv: repo.webhook_secret_iv,
        tag: repo.webhook_secret_tag,
      });

      const validator = getWebhookSignatureValidator();
      const signatureResult = validator.validate(rawPayload, signature, secret);

      if (!signatureResult.valid) {
        logger.warn({
          repositoryId: repo.id,
          deliveryId,
          error: signatureResult.error,
        }, 'Webhook signature validation failed');
        throw new Error(`Invalid webhook signature: ${signatureResult.error}`);
      }
    }

    // Create webhook event record
    const eventId = crypto.randomUUID();

    await db.execute(sql`
      INSERT INTO github_webhook_events (
        id, repository_id, event_type, delivery_id, action,
        sender_login, sender_id, ref, before_sha, after_sha,
        processed, received_at
      ) VALUES (
        ${eventId}, ${repo.id}, ${eventType}, ${deliveryId},
        ${payload.action || null}, ${payload.sender.login}, ${payload.sender.id},
        ${payload.ref || null}, ${payload.before || null}, ${payload.after || null},
        false, NOW()
      )
    `);

    const event: WebhookEvent = {
      id: eventId,
      repositoryId: repo.id,
      deliveryId,
      eventType,
      action: payload.action,
      senderLogin: payload.sender.login,
      senderId: payload.sender.id,
      ref: payload.ref,
      beforeSha: payload.before,
      afterSha: payload.after,
      processed: false,
      receivedAt: new Date(),
    };

    logger.info({
      eventId,
      eventType,
      deliveryId,
      repositoryId: repo.id,
    }, 'Webhook event received');

    return event;
  }

  /**
   * Mark a webhook event as processed
   */
  async markEventProcessed(eventId: string, scanId?: string, error?: string): Promise<void> {
    await db.execute(sql`
      UPDATE github_webhook_events
      SET
        processed = true,
        processed_at = NOW(),
        scan_id = ${scanId || null},
        error = ${error || null}
      WHERE id = ${eventId}
    `);
  }

  /**
   * Get webhook events for a repository
   */
  async getWebhookEvents(
    repositoryId: string,
    limit: number = 50
  ): Promise<WebhookEvent[]> {
    const result = await db.execute<WebhookEventRow>(sql`
      SELECT * FROM github_webhook_events
      WHERE repository_id = ${repositoryId}
      ORDER BY received_at DESC
      LIMIT ${limit}
    `);

    return result.rows.map((row) => this.rowToEvent(row));
  }

  /**
   * Get pending (unprocessed) webhook events
   */
  async getPendingEvents(limit: number = 100): Promise<WebhookEvent[]> {
    const result = await db.execute<WebhookEventRow>(sql`
      SELECT * FROM github_webhook_events
      WHERE processed = false
      ORDER BY received_at ASC
      LIMIT ${limit}
    `);

    return result.rows.map((row) => this.rowToEvent(row));
  }

  /**
   * Determine if an event should trigger a scan
   */
  shouldTriggerScan(event: WebhookEvent, repo: ConnectedRepositoryRow): boolean {
    if (!repo.auto_scan_enabled) {
      return false;
    }

    switch (event.eventType) {
      case 'push':
        return repo.scan_on_push;

      case 'pull_request':
        // Only scan on opened, synchronize (new commits), or reopened
        const triggerActions = ['opened', 'synchronize', 'reopened'];
        return repo.scan_on_pr && event.action !== undefined && triggerActions.includes(event.action);

      default:
        return false;
    }
  }

  /**
   * Get webhook configuration for a repository
   */
  async getWebhookConfig(repositoryId: string): Promise<WebhookConfig | null> {
    const repoResult = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE id = ${repositoryId}
      LIMIT 1
    `);

    if (repoResult.rows.length === 0 || !repoResult.rows[0].webhook_id) {
      return null;
    }

    // We don't return the actual secret, just indicate it exists
    return {
      url: '', // Would be determined by environment
      secret: '********', // Masked
      events: SUPPORTED_EVENTS,
    };
  }

  /**
   * Convert database row to WebhookEvent
   */
  private rowToEvent(row: WebhookEventRow): WebhookEvent {
    return {
      id: row.id,
      repositoryId: row.repository_id,
      deliveryId: row.delivery_id,
      eventType: row.event_type,
      action: row.action || undefined,
      senderLogin: row.sender_login,
      senderId: row.sender_id,
      ref: row.ref || undefined,
      beforeSha: row.before_sha || undefined,
      afterSha: row.after_sha || undefined,
      processed: row.processed,
      scanId: row.scan_id || undefined,
      error: row.error || undefined,
      receivedAt: row.received_at,
      processedAt: row.processed_at || undefined,
    };
  }

  /**
   * Cleanup old webhook events
   */
  async cleanupOldEvents(olderThanDays: number = 30): Promise<number> {
    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

    const result = await db.execute<{ count: string }>(sql`
      WITH deleted AS (
        DELETE FROM github_webhook_events
        WHERE received_at < ${cutoff}
        RETURNING *
      )
      SELECT COUNT(*) as count FROM deleted
    `);

    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    if (this.redis) {
      await this.redis.quit();
      this.redis = null;
    }
  }
}

// Singleton instance
let webhookServiceInstance: GitHubWebhookService | null = null;

/**
 * Get the singleton GitHubWebhookService instance
 */
export function getGitHubWebhookService(): GitHubWebhookService {
  if (!webhookServiceInstance) {
    webhookServiceInstance = new GitHubWebhookService();
  }
  return webhookServiceInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetGitHubWebhookService(): void {
  if (webhookServiceInstance) {
    webhookServiceInstance.close().catch(() => {});
  }
  webhookServiceInstance = null;
}
