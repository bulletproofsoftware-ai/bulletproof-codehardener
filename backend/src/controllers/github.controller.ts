/**
 * GitHub Integration Controller
 *
 * Handles all GitHub integration API endpoints:
 * - OAuth flow (initiate, callback)
 * - Connection management
 * - Repository operations
 * - Webhook management
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import { getGitHubOAuthService } from '../services/github/oauth/github-oauth.service.js';
import { getGitHubRepositoryService } from '../services/github/repository/repository.service.js';
import { getGitHubWebhookService } from '../services/github/webhook/webhook.service.js';
import { getOAuthAuditLogger } from '../services/github/oauth/oauth-audit-logger.js';
import { getWebhookData } from '../middleware/webhookSignature.js';
import { recordOAuthFailure, clearOAuthBackoff } from '../middleware/githubRateLimiter.js';
import { sendSuccess, sendCreated, sendError, sendValidationError } from '../utils/apiResponse.js';
import { logger } from '../utils/logger.js';
import { addScanJob } from '../services/queue/scan.queue.js';
import { buildScanContext } from '../services/scan-context.js';
import { db } from '../db/client.js';
import { sql } from 'drizzle-orm';

/** Row shape for scan RETURNING id */
interface ScanIdRow {
  id: string;
}

// ============================================================================
// Validation Schemas
// ============================================================================

const initOAuthSchema = z.object({
  redirectUri: z.string().url().optional(),
});

const callbackSchema = z.object({
  code: z.string().min(1),
  state: z.string().min(1),
});

const connectRepoSchema = z.object({
  connectionId: z.string().uuid(),
  repoFullName: z.string().regex(/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/),
  projectId: z.string().uuid(),
  autoScan: z.boolean().optional().default(true),
  scanOnPush: z.boolean().optional().default(true),
  scanOnPr: z.boolean().optional().default(true),
  scanProfile: z.string().optional().default('standard'),
});

const updateRepoSettingsSchema = z.object({
  autoScanEnabled: z.boolean().optional(),
  scanOnPush: z.boolean().optional(),
  scanOnPr: z.boolean().optional(),
  scanProfile: z.string().optional(),
});

const listReposQuerySchema = z.object({
  connectionId: z.string().uuid(),
  page: z.coerce.number().int().positive().optional().default(1),
  perPage: z.coerce.number().int().min(1).max(100).optional().default(30),
  type: z.enum(['all', 'owner', 'member']).optional().default('all'),
  sort: z.enum(['created', 'updated', 'pushed', 'full_name']).optional().default('pushed'),
  direction: z.enum(['asc', 'desc']).optional().default('desc'),
});

const listOrgReposQuerySchema = z.object({
  connectionId: z.string().uuid(),
  org: z.string().min(1),
  page: z.coerce.number().int().positive().optional().default(1),
  perPage: z.coerce.number().int().min(1).max(100).optional().default(30),
  type: z.enum(['all', 'public', 'private', 'forks', 'sources', 'member']).optional().default('all'),
});

const triggerScanSchema = z.object({
  branch: z.string().optional(),
  profile: z.string().optional(),
});

const createWebhookSchema = z.object({
  webhookUrl: z.string().url(),
});

// ============================================================================
// OAuth Endpoints
// ============================================================================

/**
 * Initiate GitHub OAuth flow
 * POST /api/v1/github/oauth/authorize
 */
export async function initiateOAuth(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const parsed = initOAuthSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const oauthService = getGitHubOAuthService();
    const result = await oauthService.initializeOAuth(user.id, parsed.data.redirectUri);

    sendSuccess(res, result);
  } catch (error) {
    logger.error({ error }, 'OAuth initiation failed');
    sendError(res, 'INTERNAL_ERROR', 'Failed to initiate OAuth flow', 500);
  }
}

/**
 * Handle GitHub OAuth callback
 * POST /api/v1/github/oauth/callback
 */
export async function handleOAuthCallback(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const parsed = callbackSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const { code, state } = parsed.data;

    const oauthService = getGitHubOAuthService();

    try {
      const connection = await oauthService.exchangeCodeForToken(code, state, user.id);

      // Clear any backoff on successful auth
      await clearOAuthBackoff(user.id);

      // Audit log: token creation (SEC-026)
      const auditLogger = getOAuthAuditLogger();
      await auditLogger.logTokenCreated(user.id, req, {
        scopes: connection.tokenScope ? connection.tokenScope.split(',').map((s: string) => s.trim()) : [],
        githubUsername: connection.githubUsername,
        githubUserId: connection.githubUserId,
        connectionId: connection.id,
      }).catch((auditError) => {
        logger.error({ error: auditError }, 'Failed to write OAuth audit log');
      });

      sendCreated(res, {
        id: connection.id,
        githubUsername: connection.githubUsername,
        githubAvatarUrl: connection.githubAvatarUrl,
        status: connection.status,
        tokenScope: connection.tokenScope,
        createdAt: connection.createdAt,
      });
    } catch (error) {
      // Record failure for backoff
      await recordOAuthFailure(user.id);

      // Audit log: validation failure (SEC-026)
      const auditLogger = getOAuthAuditLogger();
      await auditLogger.logValidationFailed(user.id, req, {
        reason: 'OAuth token exchange failed',
        errorMessage: (error as Error).message,
      }).catch((auditError) => {
        logger.error({ error: auditError }, 'Failed to write OAuth audit log');
      });

      if ((error as Error).message.includes('Invalid or expired OAuth state')) {
        sendError(res, 'BAD_REQUEST', 'Invalid or expired OAuth state. Please try again.', 400);
        return;
      }

      throw error;
    }
  } catch (error) {
    logger.error({ error }, 'OAuth callback failed');
    sendError(res, 'INTERNAL_ERROR', 'OAuth authentication failed', 500);
  }
}

// ============================================================================
// Connection Endpoints
// ============================================================================

/**
 * Get all GitHub connections for current user
 * GET /api/v1/github/connections
 */
export async function getConnections(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const oauthService = getGitHubOAuthService();
    const connections = await oauthService.getUserConnections(user.id);

    sendSuccess(res, {
      connections: connections.map((c) => ({
        id: c.id,
        githubUserId: c.githubUserId,
        githubUsername: c.githubUsername,
        githubAvatarUrl: c.githubAvatarUrl,
        githubEmail: c.githubEmail,
        status: c.status,
        tokenScope: c.tokenScope,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      })),
    });
  } catch (error) {
    logger.error({ error }, 'Failed to get connections');
    sendError(res, 'INTERNAL_ERROR', 'Failed to retrieve connections', 500);
  }
}

/**
 * Get a specific GitHub connection
 * GET /api/v1/github/connections/:connectionId
 */
export async function getConnection(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { connectionId } = z.object({ connectionId: z.string().uuid() }).parse(req.params);

    const oauthService = getGitHubOAuthService();
    const connection = await oauthService.getConnection(connectionId, user.id);

    if (!connection) {
      sendError(res, 'NOT_FOUND', 'Connection not found', 404);
      return;
    }

    sendSuccess(res, {
      id: connection.id,
      githubUserId: connection.githubUserId,
      githubUsername: connection.githubUsername,
      githubAvatarUrl: connection.githubAvatarUrl,
      githubEmail: connection.githubEmail,
      status: connection.status,
      tokenScope: connection.tokenScope,
      createdAt: connection.createdAt,
      lastUsedAt: connection.lastUsedAt,
    });
  } catch (error) {
    logger.error({ error }, 'Failed to get connection');
    sendError(res, 'INTERNAL_ERROR', 'Failed to retrieve connection', 500);
  }
}

/**
 * Revoke a GitHub connection
 * DELETE /api/v1/github/connections/:connectionId
 */
export async function revokeConnection(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { connectionId } = z.object({ connectionId: z.string().uuid() }).parse(req.params);

    const oauthService = getGitHubOAuthService();
    const revoked = await oauthService.revokeConnection(connectionId, user.id);

    if (!revoked) {
      sendError(res, 'NOT_FOUND', 'Connection not found', 404);
      return;
    }

    // Audit log: token revocation (SEC-026)
    const auditLogger = getOAuthAuditLogger();
    await auditLogger.logTokenRevoked(user.id, req, {
      connectionId,
      reason: 'User-initiated revocation',
      revokedBy: 'user',
    }).catch((auditError) => {
      logger.error({ error: auditError }, 'Failed to write OAuth audit log');
    });

    sendSuccess(res, { message: 'Connection revoked successfully' });
  } catch (error) {
    logger.error({ error }, 'Failed to revoke connection');
    sendError(res, 'INTERNAL_ERROR', 'Failed to revoke connection', 500);
  }
}

// ============================================================================
// Repository Endpoints
// ============================================================================

/**
 * List GitHub repositories from connection
 * GET /api/v1/github/repositories
 */
export async function listRepositories(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const parsed = listReposQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const result = await repoService.listUserRepositories(parsed.data);

    sendSuccess(res, {
      repositories: result.repositories,
      hasMore: result.hasMore,
      page: parsed.data.page,
      perPage: parsed.data.perPage,
    });
  } catch (error) {
    logger.error({ error }, 'Failed to list repositories');
    sendError(res, 'INTERNAL_ERROR', 'Failed to list repositories', 500);
  }
}

/**
 * List organization repositories
 * GET /api/v1/github/organizations/:org/repositories
 */
export async function listOrgRepositories(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { org } = z.object({ org: z.string().min(1) }).parse(req.params);
    const query = {
      ...req.query,
      org,
    };

    const parsed = listOrgReposQuerySchema.safeParse(query);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const result = await repoService.listOrgRepositories(parsed.data);

    sendSuccess(res, {
      repositories: result.repositories,
      hasMore: result.hasMore,
      page: parsed.data.page,
      perPage: parsed.data.perPage,
    });
  } catch (error) {
    logger.error({ error }, 'Failed to list org repositories');
    sendError(res, 'INTERNAL_ERROR', 'Failed to list organization repositories', 500);
  }
}

/**
 * List user's GitHub organizations
 * GET /api/v1/github/organizations
 */
export async function listOrganizations(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { connectionId } = z.object({ connectionId: z.string().uuid() }).passthrough().parse(req.query);
    if (!connectionId) {
      sendError(res, 'BAD_REQUEST', 'connectionId query parameter is required', 400);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const organizations = await repoService.listOrganizations(connectionId);

    sendSuccess(res, { organizations });
  } catch (error) {
    logger.error({ error }, 'Failed to list organizations');
    sendError(res, 'INTERNAL_ERROR', 'Failed to list organizations', 500);
  }
}

/**
 * Connect a repository to a project
 * POST /api/v1/github/repositories/connect
 */
export async function connectRepository(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const parsed = connectRepoSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const connectedRepo = await repoService.connectRepository(user.id, parsed.data);

    sendCreated(res, connectedRepo);
  } catch (error) {
    const message = (error as Error).message;

    if (message.includes('already connected')) {
      sendError(res, 'CONFLICT', message, 409);
      return;
    }

    if (message.includes('not found')) {
      sendError(res, 'NOT_FOUND', message, 404);
      return;
    }

    if (message.includes('validation failed')) {
      sendError(res, 'BAD_REQUEST', message, 400);
      return;
    }

    logger.error({ error }, 'Failed to connect repository');
    sendError(res, 'INTERNAL_ERROR', 'Failed to connect repository', 500);
  }
}

/**
 * Get connected repositories
 * GET /api/v1/github/connected
 */
export async function getConnectedRepositories(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { projectId } = z.object({ projectId: z.string().uuid().optional() }).passthrough().parse(req.query);

    const repoService = getGitHubRepositoryService();
    const repositories = await repoService.listConnectedRepositories(user.id, projectId);

    sendSuccess(res, { repositories });
  } catch (error) {
    logger.error({ error }, 'Failed to get connected repositories');
    sendError(res, 'INTERNAL_ERROR', 'Failed to retrieve connected repositories', 500);
  }
}

/**
 * Get a specific connected repository
 * GET /api/v1/github/connected/:repositoryId
 */
export async function getConnectedRepository(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const repoService = getGitHubRepositoryService();
    const repository = await repoService.getConnectedRepository(repositoryId, user.id);

    if (!repository) {
      sendError(res, 'NOT_FOUND', 'Repository not found', 404);
      return;
    }

    sendSuccess(res, repository);
  } catch (error) {
    logger.error({ error }, 'Failed to get connected repository');
    sendError(res, 'INTERNAL_ERROR', 'Failed to retrieve repository', 500);
  }
}

/**
 * Update connected repository settings
 * PATCH /api/v1/github/connected/:repositoryId
 */
export async function updateRepositorySettings(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const parsed = updateRepoSettingsSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const repository = await repoService.updateRepositorySettings(
      repositoryId,
      user.id,
      parsed.data
    );

    if (!repository) {
      sendError(res, 'NOT_FOUND', 'Repository not found', 404);
      return;
    }

    sendSuccess(res, repository);
  } catch (error) {
    logger.error({ error }, 'Failed to update repository settings');
    sendError(res, 'INTERNAL_ERROR', 'Failed to update repository settings', 500);
  }
}

/**
 * Disconnect a repository
 * DELETE /api/v1/github/connected/:repositoryId
 */
export async function disconnectRepository(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const repoService = getGitHubRepositoryService();
    const disconnected = await repoService.disconnectRepository(repositoryId, user.id);

    if (!disconnected) {
      sendError(res, 'NOT_FOUND', 'Repository not found', 404);
      return;
    }

    sendSuccess(res, { message: 'Repository disconnected successfully' });
  } catch (error) {
    logger.error({ error }, 'Failed to disconnect repository');
    sendError(res, 'INTERNAL_ERROR', 'Failed to disconnect repository', 500);
  }
}

/**
 * Trigger a scan for a repository
 * POST /api/v1/github/connected/:repositoryId/scan
 */
export async function triggerScan(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const parsed = triggerScanSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const repoService = getGitHubRepositoryService();
    const repository = await repoService.getConnectedRepository(repositoryId, user.id);

    if (!repository) {
      sendError(res, 'NOT_FOUND', 'Repository not found', 404);
      return;
    }

    // Clone the repository
    const cloneResult = await repoService.cloneRepository(repositoryId, user.id, {
      branch: parsed.data.branch,
    });

    // Create scan and queue job
    const scanResult = await db.execute(sql`
      INSERT INTO scans (project_id, status, trigger_type, branch, commit_sha, profile)
      VALUES (${repository.projectId}, 'pending', 'github_manual', ${cloneResult.branch}, ${cloneResult.commit}, ${parsed.data.profile || 'standard'})
      RETURNING id
    `);
    const scanId = (scanResult.rows[0] as unknown as ScanIdRow).id;

    // Fetch DAST context from project
    const scanContext = await buildScanContext(repository.projectId!);

    await addScanJob({
      scanId,
      projectId: repository.projectId!,
      userId: user.id,
      profile: (parsed.data.profile as 'quick' | 'standard' | 'comprehensive') || 'standard',
      branch: cloneResult.branch,
      commitSha: cloneResult.commit,
      scanners: [],
      ...scanContext,
    });

    sendCreated(res, {
      message: 'Scan triggered successfully',
      scanId,
      cloneId: cloneResult.cloneId,
      branch: cloneResult.branch,
      commit: cloneResult.commit,
    });
  } catch (error) {
    logger.error({ error }, 'Failed to trigger scan');
    sendError(res, 'INTERNAL_ERROR', 'Failed to trigger scan', 500);
  }
}

// ============================================================================
// Webhook Endpoints
// ============================================================================

/**
 * Create a webhook for a repository
 * POST /api/v1/github/connected/:repositoryId/webhook
 */
export async function createWebhook(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const parsed = createWebhookSchema.safeParse(req.body);
    if (!parsed.success) {
      sendValidationError(res, parsed.error.errors);
      return;
    }

    const webhookService = getGitHubWebhookService();
    const result = await webhookService.createWebhook(
      repositoryId,
      user.id,
      parsed.data.webhookUrl
    );

    sendCreated(res, {
      webhookId: result.webhookId,
      message: 'Webhook created successfully',
    });
  } catch (error) {
    logger.error({ error }, 'Failed to create webhook');
    sendError(res, 'INTERNAL_ERROR', 'Failed to create webhook', 500);
  }
}

/**
 * Delete a webhook
 * DELETE /api/v1/github/connected/:repositoryId/webhook
 */
export async function deleteWebhook(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);

    const webhookService = getGitHubWebhookService();
    await webhookService.deleteWebhook(repositoryId, user.id);

    sendSuccess(res, { message: 'Webhook deleted successfully' });
  } catch (error) {
    logger.error({ error }, 'Failed to delete webhook');
    sendError(res, 'INTERNAL_ERROR', 'Failed to delete webhook', 500);
  }
}

/**
 * Handle incoming webhook from GitHub
 * POST /api/v1/github/webhooks/receive
 */
export async function receiveWebhook(req: Request, res: Response): Promise<void> {
  try {
    const webhookData = getWebhookData(req);

    if (!webhookData) {
      sendError(res, 'INTERNAL_ERROR', 'Webhook data not available', 500);
      return;
    }

    const { eventType, deliveryId, payload } = webhookData;

    const webhookService = getGitHubWebhookService();

    // Process the webhook event
    const event = await webhookService.processWebhookEvent(
      eventType,
      deliveryId,
      req.headers['x-hub-signature-256'] as string,
      payload,
      req.rawBody || ''
    );

    // Determine if we should trigger a scan
    const shouldScan = webhookService.shouldTriggerScan(event, webhookData.repository);

    if (shouldScan && event.repositoryId) {
      // Queue scan from webhook event
      try {
        const repoService = getGitHubRepositoryService();
        const repo = await repoService.getConnectedRepository(event.repositoryId, '');

        if (repo?.projectId) {
          const scanResult = await db.execute(sql`
            INSERT INTO scans (project_id, status, trigger_type, branch, commit_sha, profile)
            VALUES (${repo.projectId}, 'pending', 'github_webhook', ${event.ref || 'main'}, ${event.afterSha || null}, 'standard')
            RETURNING id
          `);
          const scanId = (scanResult.rows[0] as unknown as ScanIdRow).id;

          // Fetch DAST context from project
          const webhookScanContext = await buildScanContext(repo.projectId!);

          await addScanJob({
            scanId,
            projectId: repo.projectId!,
            userId: repo.userId || 'webhook',
            profile: 'standard',
            branch: event.ref || 'main',
            commitSha: event.afterSha,
            scanners: [],
            ...webhookScanContext,
          });

          logger.info({
            eventId: event.id,
            eventType,
            repositoryId: event.repositoryId,
            scanId,
          }, 'Scan triggered from webhook');
        }
      } catch (scanError) {
        logger.error({ error: scanError, eventId: event.id }, 'Failed to queue webhook scan');
      }
    }

    sendSuccess(res, {
      eventId: event.id,
      processed: true,
      scanTriggered: shouldScan,
    });
  } catch (error) {
    const message = (error as Error).message;

    if (message.includes('Duplicate webhook delivery')) {
      sendSuccess(res, { message: 'Webhook already processed', duplicate: true });
      return;
    }

    logger.error({ error }, 'Failed to process webhook');
    sendError(res, 'INTERNAL_ERROR', 'Failed to process webhook', 500);
  }
}

/**
 * Get webhook events for a repository
 * GET /api/v1/github/connected/:repositoryId/webhook/events
 */
export async function getWebhookEvents(req: Request, res: Response): Promise<void> {
  try {
    const user = req.user;
    if (!user?.id) {
      sendError(res, 'UNAUTHORIZED', 'Authentication required', 401);
      return;
    }

    const { repositoryId } = z.object({ repositoryId: z.string().uuid() }).parse(req.params);
    const { limit } = z.object({ limit: z.coerce.number().int().min(1).max(200).default(50) }).passthrough().parse(req.query);

    const webhookService = getGitHubWebhookService();
    const events = await webhookService.getWebhookEvents(repositoryId, limit);

    sendSuccess(res, { events });
  } catch (error) {
    logger.error({ error }, 'Failed to get webhook events');
    sendError(res, 'INTERNAL_ERROR', 'Failed to retrieve webhook events', 500);
  }
}
