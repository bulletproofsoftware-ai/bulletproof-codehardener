/**
 * GitHub Integration Routes
 *
 * API endpoints for GitHub OAuth, repository management, and webhooks.
 */

import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import {
  oauthCallbackRateLimiter,
  oauthInitRateLimiter,
  oauthBackoffMiddleware,
} from '../middleware/githubRateLimiter.js';
import { verifyWebhookSignature } from '../middleware/webhookSignature.js';
import {
  initiateOAuth,
  handleOAuthCallback,
  getConnections,
  getConnection,
  revokeConnection,
  listRepositories,
  listOrgRepositories,
  listOrganizations,
  connectRepository,
  getConnectedRepositories,
  getConnectedRepository,
  updateRepositorySettings,
  disconnectRepository,
  triggerScan,
  createWebhook,
  deleteWebhook,
  receiveWebhook,
  getWebhookEvents,
} from '../controllers/github.controller.js';

const router = Router();

// ============================================================================
// OAuth Routes
// ============================================================================

/**
 * @route POST /api/v1/github/oauth/authorize
 * @desc Initiate GitHub OAuth flow
 * @access Private
 */
router.post(
  '/oauth/authorize',
  authenticate,
  oauthInitRateLimiter,
  initiateOAuth
);

/**
 * @route POST /api/v1/github/oauth/callback
 * @desc Handle GitHub OAuth callback
 * @access Private
 */
router.post(
  '/oauth/callback',
  authenticate,
  oauthCallbackRateLimiter,
  oauthBackoffMiddleware,
  handleOAuthCallback
);

// ============================================================================
// Connection Routes
// ============================================================================

/**
 * @route GET /api/v1/github/connections
 * @desc Get all GitHub connections for current user
 * @access Private
 */
router.get('/connections', authenticate, getConnections);

/**
 * @route GET /api/v1/github/connections/:connectionId
 * @desc Get a specific GitHub connection
 * @access Private
 */
router.get('/connections/:connectionId', authenticate, getConnection);

/**
 * @route DELETE /api/v1/github/connections/:connectionId
 * @desc Revoke a GitHub connection
 * @access Private
 */
router.delete('/connections/:connectionId', authenticate, revokeConnection);

// ============================================================================
// Repository Listing Routes (from GitHub API)
// ============================================================================

/**
 * @route GET /api/v1/github/repositories
 * @desc List GitHub repositories from connection
 * @access Private
 * @query connectionId - Required GitHub connection ID
 * @query page - Page number (default: 1)
 * @query perPage - Items per page (default: 30, max: 100)
 * @query type - Repository type filter (all, owner, member)
 * @query sort - Sort field (created, updated, pushed, full_name)
 * @query direction - Sort direction (asc, desc)
 */
router.get('/repositories', authenticate, listRepositories);

/**
 * @route GET /api/v1/github/organizations
 * @desc List user's GitHub organizations
 * @access Private
 * @query connectionId - Required GitHub connection ID
 */
router.get('/organizations', authenticate, listOrganizations);

/**
 * @route GET /api/v1/github/organizations/:org/repositories
 * @desc List organization repositories
 * @access Private
 * @query connectionId - Required GitHub connection ID
 * @query page - Page number (default: 1)
 * @query perPage - Items per page (default: 30, max: 100)
 * @query type - Repository type filter (all, public, private, forks, sources, member)
 */
router.get('/organizations/:org/repositories', authenticate, listOrgRepositories);

// ============================================================================
// Connected Repository Routes
// ============================================================================

/**
 * @route POST /api/v1/github/repositories/connect
 * @desc Connect a repository to a project
 * @access Private
 * @body connectionId - GitHub connection ID
 * @body repoFullName - Repository full name (owner/repo)
 * @body projectId - Project ID to connect to
 * @body autoScan - Enable automatic scanning (default: true)
 * @body scanOnPush - Scan on push events (default: true)
 * @body scanOnPr - Scan on pull request events (default: true)
 * @body scanProfile - Scan profile to use (default: 'standard')
 */
router.post('/repositories/connect', authenticate, connectRepository);

/**
 * @route GET /api/v1/github/connected
 * @desc Get all connected repositories
 * @access Private
 * @query projectId - Optional project ID filter
 */
router.get('/connected', authenticate, getConnectedRepositories);

/**
 * @route GET /api/v1/github/connected/:repositoryId
 * @desc Get a specific connected repository
 * @access Private
 */
router.get('/connected/:repositoryId', authenticate, getConnectedRepository);

/**
 * @route PATCH /api/v1/github/connected/:repositoryId
 * @desc Update connected repository settings
 * @access Private
 * @body autoScanEnabled - Enable/disable automatic scanning
 * @body scanOnPush - Enable/disable scan on push
 * @body scanOnPr - Enable/disable scan on PR
 * @body scanProfile - Scan profile name
 */
router.patch('/connected/:repositoryId', authenticate, updateRepositorySettings);

/**
 * @route DELETE /api/v1/github/connected/:repositoryId
 * @desc Disconnect a repository
 * @access Private
 */
router.delete('/connected/:repositoryId', authenticate, disconnectRepository);

/**
 * @route POST /api/v1/github/connected/:repositoryId/scan
 * @desc Trigger a scan for a connected repository
 * @access Private
 * @body branch - Optional branch to scan (default: default branch)
 * @body profile - Optional scan profile override
 */
router.post('/connected/:repositoryId/scan', authenticate, triggerScan);

// ============================================================================
// Webhook Routes
// ============================================================================

/**
 * @route POST /api/v1/github/connected/:repositoryId/webhook
 * @desc Create a webhook for a repository
 * @access Private
 * @body webhookUrl - URL to receive webhook events
 */
router.post('/connected/:repositoryId/webhook', authenticate, createWebhook);

/**
 * @route DELETE /api/v1/github/connected/:repositoryId/webhook
 * @desc Delete a webhook
 * @access Private
 */
router.delete('/connected/:repositoryId/webhook', authenticate, deleteWebhook);

/**
 * @route GET /api/v1/github/connected/:repositoryId/webhook/events
 * @desc Get webhook events for a repository
 * @access Private
 * @query limit - Maximum events to return (default: 50)
 */
router.get('/connected/:repositoryId/webhook/events', authenticate, getWebhookEvents);

/**
 * @route POST /api/v1/github/webhooks/receive
 * @desc Receive webhook events from GitHub
 * @access Public (verified by signature)
 */
router.post('/webhooks/receive', verifyWebhookSignature, receiveWebhook);

export const githubRoutes = router;
