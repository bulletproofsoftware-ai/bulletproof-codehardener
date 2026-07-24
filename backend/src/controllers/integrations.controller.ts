import { Request, Response } from 'express';
import { pool } from '../db/client.js';
import { createLogger } from '../utils/logger.js';
import { apiSuccess, apiError } from '../utils/apiResponse.js';
import crypto from 'node:crypto';

const logger = createLogger('integrations-controller');

interface Integration {
  id: string;
  user_id: string;
  provider: string;
  name: string;
  config: Record<string, unknown>;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}

const INTEGRATION_METADATA: Record<string, { name: string; description: string }> = {
  github: {
    name: 'GitHub',
    description: 'Connect repositories for automatic scanning',
  },
  gitlab: {
    name: 'GitLab',
    description: 'Connect repositories for automatic scanning',
  },
  slack: {
    name: 'Slack',
    description: 'Get notifications in Slack channels',
  },
  webhooks: {
    name: 'Webhooks',
    description: 'Send scan results to custom endpoints',
  },
  jira: {
    name: 'Jira',
    description: 'Create issues for security findings',
  },
  linear: {
    name: 'Linear',
    description: 'Create issues for security findings',
  },
};

// List all integrations
export async function listIntegrations(req: Request, res: Response) {
  const userId = req.user!.id;

  const result = await pool.query<Integration>(
    `SELECT id, provider, name, config, is_active, created_at
     FROM integrations
     WHERE user_id = $1`,
    [userId]
  );

  const connectedProviders = new Map<string, {
    id: string;
    name: string;
    config: Record<string, unknown>;
    createdAt: string;
  }>();

  for (const row of result.rows) {
    if (row.is_active) {
      connectedProviders.set(row.provider, {
        id: row.id,
        name: row.name,
        config: row.config || {},
        createdAt: row.created_at.toISOString(),
      });
    }
  }

  const integrations = Object.entries(INTEGRATION_METADATA).map(([provider, meta]) => {
    const connected = connectedProviders.get(provider);
    return {
      id: connected?.id || provider,
      provider,
      name: meta.name,
      description: meta.description,
      connected: !!connected,
      connectedAt: connected?.createdAt,
      details: connected ? getIntegrationDetails(provider, connected.config) : undefined,
    };
  });

  return apiSuccess(res, integrations);
}

// Get specific integration
export async function getIntegration(req: Request, res: Response) {
  const userId = req.user!.id;
  const { provider } = req.params;

  const meta = INTEGRATION_METADATA[provider];
  if (!meta) {
    return apiError(res, 'Integration not found', 404);
  }

  const result = await pool.query<Integration>(
    `SELECT id, provider, name, config, is_active, created_at
     FROM integrations
     WHERE user_id = $1 AND provider = $2`,
    [userId, provider]
  );

  const row = result.rows[0];
  const connected = row && row.is_active;

  return apiSuccess(res, {
    id: row?.id || provider,
    provider,
    name: meta.name,
    description: meta.description,
    connected: !!connected,
    config: connected ? sanitizeConfig(row.config) : {},
    connectedAt: connected ? row.created_at.toISOString() : null,
  });
}

// Connect integration
export async function connectIntegration(req: Request, res: Response) {
  const userId = req.user!.id;
  const { provider } = req.params;
  const { accessToken, config } = req.body || {};

  const meta = INTEGRATION_METADATA[provider];
  if (!meta) {
    return apiError(res, 'Integration not found', 404);
  }

  // For OAuth-based integrations, return OAuth URL
  if (!accessToken && ['github', 'gitlab', 'slack'].includes(provider)) {
    const oauthUrl = getOAuthUrl(provider);
    return apiSuccess(res, {
      id: provider,
      message: 'Redirect to OAuth provider',
      oauthUrl,
    });
  }

  // Check if integration already exists
  const existing = await pool.query(
    `SELECT id FROM integrations WHERE user_id = $1 AND provider = $2`,
    [userId, provider]
  );

  const integrationConfig = config || {};

  if (existing.rows.length > 0) {
    // Update existing
    await pool.query(
      `UPDATE integrations
       SET is_active = true, config = $1, updated_at = NOW()
       WHERE id = $2`,
      [JSON.stringify(integrationConfig), existing.rows[0].id]
    );

    logger.info({ integrationId: existing.rows[0].id, userId }, 'Integration reconnected');

    return apiSuccess(res, {
      id: existing.rows[0].id,
      message: `${meta.name} connected successfully`,
    });
  }

  // Create new
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO integrations (id, user_id, provider, name, config, is_active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())`,
    [id, userId, provider, meta.name, JSON.stringify(integrationConfig)]
  );

  logger.info({ integrationId: id, userId }, 'Integration connected');

  return apiSuccess(res, {
    id,
    message: `${meta.name} connected successfully`,
  });
}

// Disconnect integration
export async function disconnectIntegration(req: Request, res: Response) {
  const userId = req.user!.id;
  const { provider } = req.params;

  const meta = INTEGRATION_METADATA[provider];
  if (!meta) {
    return apiError(res, 'Integration not found', 404);
  }

  const result = await pool.query(
    `UPDATE integrations
     SET is_active = false, updated_at = NOW()
     WHERE user_id = $1 AND provider = $2
     RETURNING id`,
    [userId, provider]
  );

  if (result.rows.length === 0) {
    return apiError(res, 'Integration not connected', 404);
  }

  logger.info({ integrationId: result.rows[0].id, userId }, 'Integration disconnected');

  return apiSuccess(res, {
    message: `${meta.name} disconnected successfully`,
  });
}

// Update integration configuration
export async function updateIntegration(req: Request, res: Response) {
  const userId = req.user!.id;
  const { provider } = req.params;
  const { config } = req.body;

  const meta = INTEGRATION_METADATA[provider];
  if (!meta) {
    return apiError(res, 'Integration not found', 404);
  }

  const result = await pool.query(
    `UPDATE integrations
     SET config = $1, updated_at = NOW()
     WHERE user_id = $2 AND provider = $3 AND is_active = true
     RETURNING id`,
    [JSON.stringify(config), userId, provider]
  );

  if (result.rows.length === 0) {
    return apiError(res, 'Integration not connected', 404);
  }

  logger.info({ integrationId: result.rows[0].id, userId }, 'Integration updated');

  return apiSuccess(res, {
    message: `${meta.name} configuration updated`,
  });
}

function getIntegrationDetails(provider: string, config: Record<string, unknown>): string | undefined {
  switch (provider) {
    case 'github':
      return config.repos ? `${(config.repos as string[]).length} repos` : undefined;
    case 'slack':
      return config.channel ? `#${config.channel}` : '#notifications';
    default:
      return undefined;
  }
}

function sanitizeConfig(config: Record<string, unknown>): Record<string, unknown> {
  const sanitized = { ...config };
  delete sanitized.accessToken;
  delete sanitized.refreshToken;
  delete sanitized.secret;
  return sanitized;
}

function getOAuthUrl(provider: string): string {
  // In production, these would be actual OAuth URLs with proper client_id and redirect_uri
  const baseUrls: Record<string, string> = {
    github: 'https://github.com/login/oauth/authorize',
    gitlab: 'https://gitlab.com/oauth/authorize',
    slack: 'https://slack.com/oauth/v2/authorize',
  };
  return baseUrls[provider] || '';
}
