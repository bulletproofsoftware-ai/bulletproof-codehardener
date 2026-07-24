/**
 * GitHub Repository Service (GH-011, GH-012, GH-020, GH-031, GH-032)
 *
 * Manages GitHub repository operations:
 * - List user/organization repositories
 * - Connect repositories to projects
 * - Clone repositories for scanning
 * - Repository configuration management
 */

import crypto from 'crypto';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import { db } from '../../../db/client.js';
import { sql } from 'drizzle-orm';
import { getGitHubOAuthService } from '../oauth/github-oauth.service.js';
import { getSSRFValidator } from '../security/ssrf-validator.js';
import { logger } from '../../../utils/logger.js';
import type {
  GitHubRepository,
  ConnectedRepository,
  ConnectedRepositoryRow,
  GitHubOrganization,
  CloneOptions,
  CloneResult,
  CleanupRecord,
  ListRepositoriesQuery,
  ListOrgRepositoriesQuery,
  ConnectRepositoryRequest,
} from '../../../types/github.types.js';

const GITHUB_API_URL = 'https://api.github.com';
const DEFAULT_CLONE_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const DEFAULT_CLONE_DEPTH = 1; // Shallow clone by default
const CLONE_BASE_DIR = path.join(os.tmpdir(), 'codehardener-clones');

// Track active clones for cleanup
const activeClones = new Map<string, CleanupRecord>();

export class GitHubRepositoryService {
  /**
   * List repositories for a user's GitHub connection
   */
  async listUserRepositories(
    query: ListRepositoriesQuery
  ): Promise<{ repositories: GitHubRepository[]; hasMore: boolean }> {
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(query.connectionId, ''); // userId handled in route

    if (!accessToken) {
      throw new Error('GitHub connection not found or token unavailable');
    }

    const params = new URLSearchParams({
      page: String(query.page || 1),
      per_page: String(query.perPage || 30),
      type: query.type || 'all',
      sort: query.sort || 'pushed',
      direction: query.direction || 'desc',
    });

    const response = await fetch(`${GITHUB_API_URL}/user/repos?${params}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to list repositories: ${response.status}`);
    }

    const data = await response.json() as Array<{
      id: number;
      owner: { login: string };
      name: string;
      full_name: string;
      description?: string;
      default_branch: string;
      private: boolean;
      html_url: string;
      clone_url: string;
      size: number;
      language?: string;
      pushed_at?: string;
    }>;

    // Check for pagination
    const linkHeader = response.headers.get('Link');
    const hasMore = linkHeader?.includes('rel="next"') || false;

    return {
      repositories: data.map((repo) => ({
        id: repo.id,
        owner: repo.owner.login,
        name: repo.name,
        fullName: repo.full_name,
        description: repo.description,
        defaultBranch: repo.default_branch,
        isPrivate: repo.private,
        htmlUrl: repo.html_url,
        cloneUrl: repo.clone_url,
        size: repo.size,
        language: repo.language,
        pushedAt: repo.pushed_at ? new Date(repo.pushed_at) : undefined,
      })),
      hasMore,
    };
  }

  /**
   * List repositories for an organization
   */
  async listOrgRepositories(
    query: ListOrgRepositoriesQuery
  ): Promise<{ repositories: GitHubRepository[]; hasMore: boolean }> {
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(query.connectionId, '');

    if (!accessToken) {
      throw new Error('GitHub connection not found or token unavailable');
    }

    const params = new URLSearchParams({
      page: String(query.page || 1),
      per_page: String(query.perPage || 30),
      type: query.type || 'all',
    });

    const response = await fetch(`${GITHUB_API_URL}/orgs/${query.org}/repos?${params}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(`Organization '${query.org}' not found`);
      }
      throw new Error(`Failed to list organization repositories: ${response.status}`);
    }

    const data = await response.json() as Array<{
      id: number;
      owner: { login: string };
      name: string;
      full_name: string;
      description?: string;
      default_branch: string;
      private: boolean;
      html_url: string;
      clone_url: string;
      size: number;
      language?: string;
      pushed_at?: string;
    }>;

    const linkHeader = response.headers.get('Link');
    const hasMore = linkHeader?.includes('rel="next"') || false;

    return {
      repositories: data.map((repo) => ({
        id: repo.id,
        owner: repo.owner.login,
        name: repo.name,
        fullName: repo.full_name,
        description: repo.description,
        defaultBranch: repo.default_branch,
        isPrivate: repo.private,
        htmlUrl: repo.html_url,
        cloneUrl: repo.clone_url,
        size: repo.size,
        language: repo.language,
        pushedAt: repo.pushed_at ? new Date(repo.pushed_at) : undefined,
      })),
      hasMore,
    };
  }

  /**
   * List user's GitHub organizations
   */
  async listOrganizations(connectionId: string): Promise<GitHubOrganization[]> {
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(connectionId, '');

    if (!accessToken) {
      throw new Error('GitHub connection not found or token unavailable');
    }

    const response = await fetch(`${GITHUB_API_URL}/user/orgs`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to list organizations: ${response.status}`);
    }

    const data = await response.json() as Array<{
      login: string;
      avatar_url: string;
    }>;

    return data.map((org) => ({
      login: org.login,
      avatarUrl: org.avatar_url,
    }));
  }

  /**
   * Get a single repository's details
   */
  async getRepository(connectionId: string, owner: string, repo: string): Promise<GitHubRepository> {
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(connectionId, '');

    if (!accessToken) {
      throw new Error('GitHub connection not found or token unavailable');
    }

    const response = await fetch(`${GITHUB_API_URL}/repos/${owner}/${repo}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(`Repository '${owner}/${repo}' not found`);
      }
      throw new Error(`Failed to get repository: ${response.status}`);
    }

    const data = await response.json() as {
      id: number;
      owner: { login: string };
      name: string;
      full_name: string;
      description?: string;
      default_branch: string;
      private: boolean;
      html_url: string;
      clone_url: string;
      size: number;
      language?: string;
      pushed_at?: string;
    };

    return {
      id: data.id,
      owner: data.owner.login,
      name: data.name,
      fullName: data.full_name,
      description: data.description,
      defaultBranch: data.default_branch,
      isPrivate: data.private,
      htmlUrl: data.html_url,
      cloneUrl: data.clone_url,
      size: data.size,
      language: data.language,
      pushedAt: data.pushed_at ? new Date(data.pushed_at) : undefined,
    };
  }

  /**
   * Connect a repository to a project for scanning
   */
  async connectRepository(
    userId: string,
    request: ConnectRepositoryRequest
  ): Promise<ConnectedRepository> {
    // Validate the repository URL using SSRF validator
    const ssrfValidator = getSSRFValidator();
    const [owner, repoName] = request.repoFullName.split('/');

    if (!owner || !repoName) {
      throw new Error('Invalid repository name format. Expected: owner/repo');
    }

    const repoUrl = `https://github.com/${owner}/${repoName}`;
    const validationResult = await ssrfValidator.validateGitHubUrl(repoUrl);

    if (!validationResult.valid) {
      throw new Error(`Repository URL validation failed: ${validationResult.error}`);
    }

    // Get repository details from GitHub
    const repo = await this.getRepository(request.connectionId, owner, repoName);

    const repositoryId = crypto.randomUUID();

    // Check if repository is already connected
    const existing = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE connection_id = ${request.connectionId}
        AND github_repo_id = ${repo.id}
      LIMIT 1
    `);

    if (existing.rows.length > 0) {
      throw new Error('Repository is already connected');
    }

    // Create connected repository record
    await db.execute(sql`
      INSERT INTO github_repositories (
        id, connection_id, user_id, project_id, github_repo_id,
        owner, name, full_name, description, default_branch,
        is_private, html_url, clone_url,
        webhook_active, auto_scan_enabled, scan_on_push, scan_on_pr, scan_profile,
        created_at, updated_at
      ) VALUES (
        ${repositoryId}, ${request.connectionId}, ${userId}, ${request.projectId},
        ${repo.id}, ${owner}, ${repoName}, ${repo.fullName},
        ${repo.description || null}, ${repo.defaultBranch},
        ${repo.isPrivate}, ${repo.htmlUrl}, ${repo.cloneUrl},
        false, ${request.autoScan ?? true}, ${request.scanOnPush ?? true},
        ${request.scanOnPr ?? true}, ${request.scanProfile || 'standard'},
        NOW(), NOW()
      )
    `);

    logger.info({
      repositoryId,
      userId,
      repoFullName: request.repoFullName,
    }, 'Repository connected');

    return {
      id: repositoryId,
      connectionId: request.connectionId,
      userId,
      projectId: request.projectId,
      githubRepoId: repo.id,
      owner,
      name: repoName,
      fullName: repo.fullName,
      description: repo.description,
      defaultBranch: repo.defaultBranch,
      isPrivate: repo.isPrivate,
      htmlUrl: repo.htmlUrl,
      cloneUrl: repo.cloneUrl,
      webhookActive: false,
      autoScanEnabled: request.autoScan ?? true,
      scanOnPush: request.scanOnPush ?? true,
      scanOnPr: request.scanOnPr ?? true,
      scanProfile: request.scanProfile || 'standard',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Get a connected repository by ID
   */
  async getConnectedRepository(repositoryId: string, userId: string): Promise<ConnectedRepository | null> {
    const result = await db.execute<ConnectedRepositoryRow>(sql`
      SELECT * FROM github_repositories
      WHERE id = ${repositoryId} AND user_id = ${userId}
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return null;
    }

    return this.rowToConnectedRepository(result.rows[0]);
  }

  /**
   * List all connected repositories for a user
   */
  async listConnectedRepositories(userId: string, projectId?: string): Promise<ConnectedRepository[]> {
    let query;

    if (projectId) {
      query = sql`
        SELECT * FROM github_repositories
        WHERE user_id = ${userId} AND project_id = ${projectId}
        ORDER BY created_at DESC
      `;
    } else {
      query = sql`
        SELECT * FROM github_repositories
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
      `;
    }

    const result = await db.execute<ConnectedRepositoryRow>(query);
    return result.rows.map((row) => this.rowToConnectedRepository(row));
  }

  /**
   * Disconnect a repository
   */
  async disconnectRepository(repositoryId: string, userId: string): Promise<boolean> {
    const result = await db.execute(sql`
      DELETE FROM github_repositories
      WHERE id = ${repositoryId} AND user_id = ${userId}
      RETURNING id
    `);

    if (result.rows.length > 0) {
      logger.info({ repositoryId, userId }, 'Repository disconnected');
      return true;
    }

    return false;
  }

  /**
   * Clone a repository for scanning (GH-031, GH-032)
   */
  async cloneRepository(
    repositoryId: string,
    userId: string,
    options: CloneOptions = {}
  ): Promise<CloneResult> {
    const connectedRepo = await this.getConnectedRepository(repositoryId, userId);
    if (!connectedRepo) {
      throw new Error('Repository not found');
    }

    // Validate URL before cloning
    const ssrfValidator = getSSRFValidator();
    const validationResult = await ssrfValidator.validateGitHubUrl(connectedRepo.cloneUrl);

    if (!validationResult.valid) {
      throw new Error(`Clone URL validation failed: ${validationResult.error}`);
    }

    // Get access token for authentication
    const oauthService = getGitHubOAuthService();
    const accessToken = await oauthService.getAccessToken(connectedRepo.connectionId, userId);

    if (!accessToken) {
      throw new Error('GitHub access token not available');
    }

    // Create unique clone directory
    const cloneId = crypto.randomUUID();
    const clonePath = path.join(CLONE_BASE_DIR, cloneId);

    // Ensure base directory exists
    await fs.mkdir(CLONE_BASE_DIR, { recursive: true });

    // Build authenticated clone URL
    const cloneUrl = new URL(connectedRepo.cloneUrl);
    cloneUrl.username = 'x-access-token';
    cloneUrl.password = accessToken;

    const branch = options.branch || connectedRepo.defaultBranch;
    const depth = options.depth || DEFAULT_CLONE_DEPTH;
    const timeout = options.timeout || DEFAULT_CLONE_TIMEOUT;

    try {
      // Import simple-git dynamically
      const { simpleGit, CleanOptions } = await import('simple-git');

      const git = simpleGit({
        timeout: {
          block: timeout,
        },
      });

      // Clone with options
      const cloneArgs = [
        '--single-branch',
        '--branch', branch,
        '--depth', String(depth),
      ];

      await git.clone(cloneUrl.toString(), clonePath, cloneArgs);

      // Get HEAD commit
      const localGit = simpleGit(clonePath);
      const log = await localGit.log({ maxCount: 1 });
      const commit = log.latest?.hash || 'unknown';

      // Clean up any untracked files
      await localGit.clean(CleanOptions.FORCE);

      // Register for cleanup
      const cleanupRecord: CleanupRecord = {
        cloneId,
        path: clonePath,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      };
      activeClones.set(cloneId, cleanupRecord);

      logger.info({
        repositoryId,
        cloneId,
        branch,
        commit: commit.substring(0, 8),
      }, 'Repository cloned');

      return {
        localPath: clonePath,
        commit,
        branch,
        cloneId,
      };
    } catch (error) {
      // Clean up on failure
      try {
        await fs.rm(clonePath, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }

      logger.error({ error, repositoryId }, 'Repository clone failed');
      throw new Error(`Clone failed: ${(error as Error).message}`);
    }
  }

  /**
   * Clean up a cloned repository
   */
  async cleanupClone(cloneId: string): Promise<void> {
    const record = activeClones.get(cloneId);
    if (!record) {
      return;
    }

    try {
      await fs.rm(record.path, { recursive: true, force: true });
      activeClones.delete(cloneId);
      logger.debug({ cloneId }, 'Clone cleaned up');
    } catch (error) {
      logger.error({ error, cloneId }, 'Clone cleanup failed');
    }
  }

  /**
   * Update repository settings
   */
  async updateRepositorySettings(
    repositoryId: string,
    userId: string,
    settings: {
      autoScanEnabled?: boolean;
      scanOnPush?: boolean;
      scanOnPr?: boolean;
      scanProfile?: string;
    }
  ): Promise<ConnectedRepository | null> {
    const updates: string[] = [];
    const values: (boolean | string)[] = [];

    if (settings.autoScanEnabled !== undefined) {
      updates.push('auto_scan_enabled');
      values.push(settings.autoScanEnabled);
    }
    if (settings.scanOnPush !== undefined) {
      updates.push('scan_on_push');
      values.push(settings.scanOnPush);
    }
    if (settings.scanOnPr !== undefined) {
      updates.push('scan_on_pr');
      values.push(settings.scanOnPr);
    }
    if (settings.scanProfile !== undefined) {
      updates.push('scan_profile');
      values.push(settings.scanProfile);
    }

    if (updates.length === 0) {
      return this.getConnectedRepository(repositoryId, userId);
    }

    // Build dynamic update query
    await db.execute(sql`
      UPDATE github_repositories
      SET
        auto_scan_enabled = COALESCE(${settings.autoScanEnabled}, auto_scan_enabled),
        scan_on_push = COALESCE(${settings.scanOnPush}, scan_on_push),
        scan_on_pr = COALESCE(${settings.scanOnPr}, scan_on_pr),
        scan_profile = COALESCE(${settings.scanProfile}, scan_profile),
        updated_at = NOW()
      WHERE id = ${repositoryId} AND user_id = ${userId}
    `);

    return this.getConnectedRepository(repositoryId, userId);
  }

  /**
   * Update last scan info
   */
  async updateLastScan(repositoryId: string, scanId: string, commit: string): Promise<void> {
    await db.execute(sql`
      UPDATE github_repositories
      SET
        last_scan_id = ${scanId},
        last_scanned_at = NOW(),
        last_scanned_commit = ${commit},
        updated_at = NOW()
      WHERE id = ${repositoryId}
    `);
  }

  /**
   * Convert database row to ConnectedRepository object
   */
  private rowToConnectedRepository(row: ConnectedRepositoryRow): ConnectedRepository {
    return {
      id: row.id,
      connectionId: row.connection_id,
      userId: row.user_id,
      projectId: row.project_id || undefined,
      githubRepoId: row.github_repo_id,
      owner: row.owner,
      name: row.name,
      fullName: row.full_name,
      description: row.description || undefined,
      defaultBranch: row.default_branch,
      isPrivate: row.is_private,
      htmlUrl: row.html_url,
      cloneUrl: row.clone_url,
      webhookId: row.webhook_id || undefined,
      webhookActive: row.webhook_active,
      autoScanEnabled: row.auto_scan_enabled,
      scanOnPush: row.scan_on_push,
      scanOnPr: row.scan_on_pr,
      scanProfile: row.scan_profile,
      lastScannedAt: row.last_scanned_at || undefined,
      lastScannedCommit: row.last_scanned_commit || undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}

// Singleton instance
let repositoryServiceInstance: GitHubRepositoryService | null = null;

/**
 * Get the singleton GitHubRepositoryService instance
 */
export function getGitHubRepositoryService(): GitHubRepositoryService {
  if (!repositoryServiceInstance) {
    repositoryServiceInstance = new GitHubRepositoryService();
  }
  return repositoryServiceInstance;
}

/**
 * Reset the singleton instance (for testing)
 */
export function resetGitHubRepositoryService(): void {
  repositoryServiceInstance = null;
}

/**
 * Get active clones for cleanup service
 */
export function getActiveClones(): Map<string, CleanupRecord> {
  return activeClones;
}
