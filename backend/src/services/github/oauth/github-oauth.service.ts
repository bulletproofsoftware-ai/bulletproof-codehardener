/**
 * GitHub OAuth Service (GH-001 to GH-005)
 *
 * Implements OAuth 2.0 flow for GitHub integration.
 * - Authorization URL generation with PKCE-like state
 * - Token exchange
 * - Token refresh
 * - Connection management
 */

import crypto from 'crypto';
import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { getTokenEncryption } from './token-encryption.js';
import { getOAuthStateManager } from './state-manager.js';
import { getOAuthAuditLogger } from './oauth-audit-logger.js';
import { logger } from '../../../utils/logger.js';
import type {
  OAuthConfig,
  OAuthInitResult,
  OAuthTokens,
  GitHubUser,
  GitHubConnection,
  GitHubConnectionRow,
} from '../../../types/github.types.js';

// GitHub OAuth configuration
const GITHUB_OAUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_API_URL = 'https://api.github.com';

// Default scopes for repository access
const DEFAULT_SCOPES = ['repo', 'read:user', 'user:email'];

export interface GitHubOAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  scopes?: string[];
}

export class GitHubOAuthService {
  private readonly config: OAuthConfig;

  constructor(config?: GitHubOAuthConfig) {
    this.config = {
      clientId: config?.clientId || process.env.GITHUB_CLIENT_ID || '',
      clientSecret: config?.clientSecret || process.env.GITHUB_CLIENT_SECRET || '',
      callbackUrl: config?.callbackUrl || process.env.GITHUB_CALLBACK_URL || '',
      scopes: config?.scopes || DEFAULT_SCOPES,
    };

    if (!this.config.clientId || !this.config.clientSecret) {
      logger.warn('GitHub OAuth credentials not configured. OAuth features will not work.');
    }
  }

  /**
   * Initialize OAuth flow - generate authorization URL with state token
   */
  async initializeOAuth(userId: string, redirectUri?: string): Promise<OAuthInitResult> {
    const stateManager = getOAuthStateManager();
    const state = await stateManager.createState(userId, redirectUri);

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      scope: this.config.scopes.join(' '),
      state: state.stateToken,
      allow_signup: 'false',
    });

    return {
      authorizationUrl: `${GITHUB_OAUTH_URL}?${params.toString()}`,
      state: state.stateToken,
    };
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(
    code: string,
    stateToken: string,
    userId: string
  ): Promise<GitHubConnection> {
    // Verify and consume state token
    const stateManager = getOAuthStateManager();
    const state = await stateManager.verifyAndConsumeState(stateToken, userId);

    if (!state) {
      throw new Error('Invalid or expired OAuth state token');
    }

    // Exchange code for token
    const tokenResponse = await fetch(GITHUB_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.callbackUrl,
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange failed: ${tokenResponse.status}`);
    }

    const tokenData = await tokenResponse.json() as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      scope?: string;
      error?: string;
      error_description?: string;
    };

    if (tokenData.error) {
      throw new Error(`GitHub OAuth error: ${tokenData.error_description || tokenData.error}`);
    }

    if (!tokenData.access_token) {
      throw new Error('No access token received from GitHub');
    }

    const tokens: OAuthTokens = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: tokenData.expires_in
        ? new Date(Date.now() + tokenData.expires_in * 1000)
        : undefined,
      scope: tokenData.scope || this.config.scopes.join(' '),
    };

    // Get GitHub user info
    const githubUser = await this.getGitHubUser(tokens.accessToken);

    // Store connection
    const connection = await this.storeConnection(userId, tokens, githubUser);

    logger.info({
      userId,
      githubUsername: githubUser.login,
    }, 'GitHub OAuth connection established');

    return connection;
  }

  /**
   * Get GitHub user information using access token
   */
  private async getGitHubUser(accessToken: string): Promise<GitHubUser> {
    const userResponse = await fetch(`${GITHUB_API_URL}/user`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!userResponse.ok) {
      throw new Error(`Failed to fetch GitHub user: ${userResponse.status}`);
    }

    const userData = await userResponse.json() as {
      id: number;
      login: string;
      avatar_url: string;
      email?: string;
      name?: string;
    };

    // Try to get primary email if not public
    let email = userData.email;
    if (!email) {
      try {
        const emailsResponse = await fetch(`${GITHUB_API_URL}/user/emails`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
        });

        if (emailsResponse.ok) {
          const emails = await emailsResponse.json() as Array<{
            email: string;
            primary: boolean;
            verified: boolean;
          }>;
          const primaryEmail = emails.find((e) => e.primary && e.verified);
          email = primaryEmail?.email;
        }
      } catch (e) {
        logger.debug({ error: e }, 'Could not fetch user emails');
      }
    }

    return {
      id: userData.id,
      login: userData.login,
      avatarUrl: userData.avatar_url,
      email,
      name: userData.name,
    };
  }

  /**
   * Store or update a GitHub connection
   */
  private async storeConnection(
    userId: string,
    tokens: OAuthTokens,
    githubUser: GitHubUser
  ): Promise<GitHubConnection> {
    const encryption = getTokenEncryption();
    const encryptedTokens = encryption.encryptTokens(tokens);

    const connectionId = crypto.randomUUID();

    // Check for existing connection
    const existing = await db.execute<GitHubConnectionRow>(sql`
      SELECT * FROM github_connections
      WHERE user_id = ${userId} AND github_user_id = ${githubUser.id}
      LIMIT 1
    `);

    if (existing.rows.length > 0) {
      // Update existing connection
      await db.execute(sql`
        UPDATE github_connections
        SET
          access_token_encrypted = ${encryptedTokens.accessToken.ciphertext},
          access_token_iv = ${encryptedTokens.accessToken.iv},
          access_token_tag = ${encryptedTokens.accessToken.tag},
          refresh_token_encrypted = ${encryptedTokens.refreshToken?.ciphertext || null},
          refresh_token_iv = ${encryptedTokens.refreshToken?.iv || null},
          refresh_token_tag = ${encryptedTokens.refreshToken?.tag || null},
          token_expires_at = ${encryptedTokens.expiresAt},
          token_scope = ${encryptedTokens.scope},
          status = 'active',
          github_username = ${githubUser.login},
          github_avatar_url = ${githubUser.avatarUrl || null},
          github_email = ${githubUser.email || null},
          updated_at = NOW()
        WHERE user_id = ${userId} AND github_user_id = ${githubUser.id}
      `);

      const row = existing.rows[0];
      return {
        id: row.id,
        userId,
        githubUserId: githubUser.id,
        githubUsername: githubUser.login,
        githubAvatarUrl: githubUser.avatarUrl,
        githubEmail: githubUser.email,
        status: 'active',
        tokenScope: encryptedTokens.scope,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at || undefined,
      };
    }

    // Create new connection
    await db.execute(sql`
      INSERT INTO github_connections (
        id, user_id, github_user_id, github_username, github_avatar_url, github_email,
        access_token_encrypted, access_token_iv, access_token_tag,
        refresh_token_encrypted, refresh_token_iv, refresh_token_tag,
        token_expires_at, token_scope, status, created_at, updated_at
      ) VALUES (
        ${connectionId}, ${userId}, ${githubUser.id}, ${githubUser.login},
        ${githubUser.avatarUrl || null}, ${githubUser.email || null},
        ${encryptedTokens.accessToken.ciphertext},
        ${encryptedTokens.accessToken.iv},
        ${encryptedTokens.accessToken.tag},
        ${encryptedTokens.refreshToken?.ciphertext || null},
        ${encryptedTokens.refreshToken?.iv || null},
        ${encryptedTokens.refreshToken?.tag || null},
        ${encryptedTokens.expiresAt},
        ${encryptedTokens.scope},
        'active',
        NOW(), NOW()
      )
    `);

    return {
      id: connectionId,
      userId,
      githubUserId: githubUser.id,
      githubUsername: githubUser.login,
      githubAvatarUrl: githubUser.avatarUrl,
      githubEmail: githubUser.email,
      status: 'active',
      tokenScope: encryptedTokens.scope,
      createdAt: new Date(),
    };
  }

  /**
   * Get a user's GitHub connection
   */
  async getConnection(connectionId: string, userId: string): Promise<GitHubConnection | null> {
    const result = await db.execute<GitHubConnectionRow>(sql`
      SELECT * FROM github_connections
      WHERE id = ${connectionId} AND user_id = ${userId}
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return null;
    }

    return this.rowToConnection(result.rows[0]);
  }

  /**
   * Get all connections for a user
   */
  async getUserConnections(userId: string): Promise<GitHubConnection[]> {
    const result = await db.execute<GitHubConnectionRow>(sql`
      SELECT * FROM github_connections
      WHERE user_id = ${userId}
      ORDER BY created_at DESC
    `);

    return result.rows.map((row) => this.rowToConnection(row));
  }

  /**
   * Get decrypted access token for a connection
   */
  async getAccessToken(connectionId: string, userId: string): Promise<string | null> {
    const result = await db.execute<GitHubConnectionRow>(sql`
      SELECT * FROM github_connections
      WHERE id = ${connectionId} AND user_id = ${userId} AND status = 'active'
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    const encryption = getTokenEncryption();

    const decryptedToken = encryption.decrypt({
      ciphertext: row.access_token_encrypted,
      iv: row.access_token_iv,
      tag: row.access_token_tag,
    });

    // Update last used timestamp
    await db.execute(sql`
      UPDATE github_connections
      SET last_used_at = NOW()
      WHERE id = ${connectionId}
    `);

    return decryptedToken;
  }

  /**
   * Revoke a GitHub connection
   */
  async revokeConnection(connectionId: string, userId: string): Promise<boolean> {
    const result = await db.execute(sql`
      UPDATE github_connections
      SET status = 'revoked', updated_at = NOW()
      WHERE id = ${connectionId} AND user_id = ${userId}
      RETURNING id
    `);

    if (result.rows.length > 0) {
      logger.info({ connectionId, userId }, 'GitHub connection revoked');
      return true;
    }

    return false;
  }

  /**
   * Delete a GitHub connection completely
   */
  async deleteConnection(connectionId: string, userId: string): Promise<boolean> {
    const result = await db.execute(sql`
      DELETE FROM github_connections
      WHERE id = ${connectionId} AND user_id = ${userId}
      RETURNING id
    `);

    if (result.rows.length > 0) {
      logger.info({ connectionId, userId }, 'GitHub connection deleted');
      return true;
    }

    return false;
  }

  /**
   * Verify connection is still valid by making a test API call
   */
  async verifyConnection(connectionId: string, userId: string): Promise<boolean> {
    const accessToken = await this.getAccessToken(connectionId, userId);
    if (!accessToken) {
      return false;
    }

    try {
      const response = await fetch(`${GITHUB_API_URL}/user`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github+json',
        },
      });

      if (response.ok) {
        return true;
      }

      if (response.status === 401) {
        // Token is invalid, mark connection as expired
        await db.execute(sql`
          UPDATE github_connections
          SET status = 'expired', updated_at = NOW()
          WHERE id = ${connectionId}
        `);

        // Audit log: connection expired (SEC-026)
        const auditLogger = getOAuthAuditLogger();
        await auditLogger.logConnectionExpired(userId, {
          connectionId,
          reason: 'GitHub token validation returned 401 - token expired or revoked',
        }).catch((auditError) => {
          logger.error({ error: auditError }, 'Failed to write OAuth audit log');
        });
      }

      return false;
    } catch (error) {
      logger.error({ error, connectionId }, 'Failed to verify GitHub connection');
      return false;
    }
  }

  /**
   * Convert database row to GitHubConnection object
   */
  private rowToConnection(row: GitHubConnectionRow): GitHubConnection {
    return {
      id: row.id,
      userId: row.user_id,
      githubUserId: row.github_user_id,
      githubUsername: row.github_username,
      githubAvatarUrl: row.github_avatar_url || undefined,
      githubEmail: row.github_email || undefined,
      status: row.status,
      tokenScope: row.token_scope,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at || undefined,
    };
  }
}

// Singleton instance
let githubOAuthServiceInstance: GitHubOAuthService | null = null;

/**
 * Get the singleton GitHubOAuthService instance
 */
export function getGitHubOAuthService(): GitHubOAuthService {
  if (!githubOAuthServiceInstance) {
    githubOAuthServiceInstance = new GitHubOAuthService();
  }
  return githubOAuthServiceInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetGitHubOAuthService(): void {
  githubOAuthServiceInstance = null;
}
