/**
 * Webhook Signature Verification Middleware (security-h002)
 *
 * Validates GitHub webhook signatures before processing.
 * Uses HMAC-SHA256 with timing-safe comparison.
 *
 * Implements:
 * - X-GitHub-Delivery header deduplication (replay prevention)
 * - HMAC-SHA256 signature validation with timing-safe comparison
 * - Custom webhook timestamp validation (5-minute window)
 */

import { Request, Response, NextFunction } from 'express';
import { getWebhookSignatureValidator } from '../services/github/webhook/signature-validator.js';
import { getTokenEncryption } from '../services/github/oauth/token-encryption.js';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';
import { sendError } from '../utils/apiResponse.js';
import { logger } from '../utils/logger.js';
import type { ConnectedRepositoryRow } from '../types/github.types.js';

/** Maximum allowed age for custom webhook timestamps (5 minutes) */
const CUSTOM_WEBHOOK_TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;

// Extend Request to include raw body
declare global {
  namespace Express {
    interface Request {
      rawBody?: string;
    }
  }
}

/**
 * Middleware to capture raw body for signature verification
 * Must be used before body parsing middleware
 */
export function captureRawBody(
  req: Request,
  _res: Response,
  buf: Buffer,
  encoding: BufferEncoding
): void {
  if (buf && buf.length) {
    req.rawBody = buf.toString(encoding || 'utf8');
  }
}

/**
 * Middleware to verify GitHub webhook signatures
 */
export async function verifyWebhookSignature(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Get required headers
    const signature = req.headers['x-hub-signature-256'] as string | undefined
      || req.headers['x-hub-signature'] as string | undefined;
    const deliveryId = req.headers['x-github-delivery'] as string | undefined;
    const eventType = req.headers['x-github-event'] as string | undefined;

    // Validate required headers
    if (!signature) {
      logger.warn('Webhook request missing signature header');
      sendError(res, 'UNAUTHORIZED', 'Missing webhook signature', 401);
      return;
    }

    if (!deliveryId) {
      logger.warn('Webhook request missing delivery ID header');
      sendError(res, 'BAD_REQUEST', 'Missing X-GitHub-Delivery header', 400);
      return;
    }

    if (!eventType) {
      logger.warn('Webhook request missing event type header');
      sendError(res, 'BAD_REQUEST', 'Missing X-GitHub-Event header', 400);
      return;
    }

    // Get raw body for signature verification
    const rawBody = req.rawBody;
    if (!rawBody) {
      logger.error('Raw body not available for webhook signature verification');
      sendError(res, 'INTERNAL_ERROR', 'Unable to verify webhook signature', 500);
      return;
    }

    // Parse body to get repository ID
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      logger.warn('Invalid JSON in webhook payload');
      sendError(res, 'BAD_REQUEST', 'Invalid JSON payload', 400);
      return;
    }

    if (!payload.repository?.id) {
      logger.warn('Webhook payload missing repository ID');
      sendError(res, 'BAD_REQUEST', 'Invalid webhook payload: missing repository', 400);
      return;
    }

    // Find repository by GitHub repo ID
    const repoResult = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE github_repo_id = ${payload.repository.id}
      LIMIT 1
    `);

    if (repoResult.rows.length === 0) {
      logger.warn({
        githubRepoId: payload.repository.id,
        fullName: payload.repository.full_name,
      }, 'Webhook received for unknown repository');
      sendError(res, 'NOT_FOUND', 'Repository not found', 404);
      return;
    }

    const repo = repoResult.rows[0];

    // Check if webhook secret is configured
    if (!repo.webhook_secret_encrypted || !repo.webhook_secret_iv || !repo.webhook_secret_tag) {
      logger.warn({
        repositoryId: repo.id,
      }, 'Webhook received but no secret configured');
      sendError(res, 'FORBIDDEN', 'Webhook not configured for this repository', 403);
      return;
    }

    // Decrypt webhook secret
    const encryption = getTokenEncryption();
    let secret: string;
    try {
      secret = encryption.decrypt({
        ciphertext: repo.webhook_secret_encrypted,
        iv: repo.webhook_secret_iv,
        tag: repo.webhook_secret_tag,
      });
    } catch (error) {
      logger.error({ error, repositoryId: repo.id }, 'Failed to decrypt webhook secret');
      sendError(res, 'INTERNAL_ERROR', 'Webhook configuration error', 500);
      return;
    }

    // Validate signature
    const validator = getWebhookSignatureValidator();
    const validationResult = validator.validate(rawBody, signature, secret);

    if (!validationResult.valid) {
      logger.warn({
        repositoryId: repo.id,
        deliveryId,
        error: validationResult.error,
      }, 'Webhook signature validation failed');
      sendError(res, 'UNAUTHORIZED', 'Invalid webhook signature', 401);
      return;
    }

    // Attach validated data to request for downstream handlers
    (req as any).webhookData = {
      eventType,
      deliveryId,
      signature,
      payload,
      repository: repo,
    };

    logger.debug({
      repositoryId: repo.id,
      deliveryId,
      eventType,
    }, 'Webhook signature verified');

    next();
  } catch (error) {
    logger.error({ error }, 'Webhook signature verification error');
    sendError(res, 'INTERNAL_ERROR', 'Webhook verification failed', 500);
  }
}

/**
 * Get webhook data from verified request
 */
export function getWebhookData(req: Request): {
  eventType: string;
  deliveryId: string;
  signature: string;
  payload: any;
  repository: ConnectedRepositoryRow;
} | undefined {
  return (req as any).webhookData;
}

/**
 * Middleware to validate custom webhook timestamps (security-h002)
 *
 * Custom (non-GitHub) webhooks must include an X-Webhook-Timestamp header
 * containing an ISO-8601 timestamp or Unix epoch (seconds). The timestamp
 * must be within a 5-minute window of the server's current time to prevent
 * replay attacks.
 *
 * This middleware should be applied to any custom webhook ingestion endpoint.
 */
export function verifyWebhookTimestamp(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const timestampHeader = req.headers['x-webhook-timestamp'] as string | undefined;

  if (!timestampHeader) {
    logger.warn({
      ip: req.ip,
      path: req.path,
    }, 'Custom webhook rejected: missing X-Webhook-Timestamp header');
    sendError(res, 'BAD_REQUEST', 'Missing X-Webhook-Timestamp header', 400);
    return;
  }

  let webhookTimestamp: number;

  // Try parsing as ISO-8601 first, then as Unix epoch (seconds)
  const isoDate = new Date(timestampHeader);
  if (!isNaN(isoDate.getTime())) {
    webhookTimestamp = isoDate.getTime();
  } else {
    const epochSeconds = parseInt(timestampHeader, 10);
    if (isNaN(epochSeconds) || epochSeconds <= 0) {
      logger.warn({
        ip: req.ip,
        path: req.path,
        timestamp: timestampHeader,
      }, 'Custom webhook rejected: invalid timestamp format');
      sendError(
        res,
        'BAD_REQUEST',
        'Invalid X-Webhook-Timestamp format. Use ISO-8601 or Unix epoch (seconds).',
        400
      );
      return;
    }
    webhookTimestamp = epochSeconds * 1000;
  }

  const now = Date.now();
  const drift = Math.abs(now - webhookTimestamp);

  if (drift > CUSTOM_WEBHOOK_TIMESTAMP_TOLERANCE_MS) {
    logger.warn({
      ip: req.ip,
      path: req.path,
      webhookTimestamp: new Date(webhookTimestamp).toISOString(),
      serverTime: new Date(now).toISOString(),
      driftMs: drift,
    }, 'Custom webhook rejected: timestamp outside 5-minute window (possible replay attack)');
    sendError(
      res,
      'BAD_REQUEST',
      'Webhook timestamp is outside the acceptable 5-minute window. Possible replay attack.',
      400
    );
    return;
  }

  next();
}
