/**
 * GitHub Integration Services
 *
 * Main export file for all GitHub integration services.
 */

// OAuth services
export {
  TokenEncryption,
  getTokenEncryption,
  resetTokenEncryption,
} from './oauth/token-encryption.js';

export {
  OAuthStateManager,
  getOAuthStateManager,
  resetOAuthStateManager,
} from './oauth/state-manager.js';

export {
  GitHubOAuthService,
  getGitHubOAuthService,
  resetGitHubOAuthService,
} from './oauth/github-oauth.service.js';

// Security services
export {
  SSRFValidator,
  getSSRFValidator,
  resetSSRFValidator,
} from './security/ssrf-validator.js';

// Repository services
export {
  GitHubRepositoryService,
  getGitHubRepositoryService,
  resetGitHubRepositoryService,
  getActiveClones,
} from './repository/repository.service.js';

export {
  CloneCleanupService,
  getCloneCleanupService,
  resetCloneCleanupService,
} from './repository/cleanup.service.js';

// Webhook services
export {
  WebhookSignatureValidator,
  getWebhookSignatureValidator,
  resetWebhookSignatureValidator,
} from './webhook/signature-validator.js';

export {
  GitHubWebhookService,
  getGitHubWebhookService,
  resetGitHubWebhookService,
} from './webhook/webhook.service.js';

// Re-export types
export * from '../../types/github.types.js';
