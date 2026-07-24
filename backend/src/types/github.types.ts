/**
 * GitHub Integration Type Definitions
 *
 * Implements: GH-001 to GH-032, SEC-001, SEC-005, SEC-008, SEC-009, SEC-017
 * Security specs: h001 (rate limiting), h002 (replay prevention), h003 (SSRF)
 */

// ============================================================================
// OAuth Types (GH-001 to GH-005)
// ============================================================================

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  scopes: string[];
}

export interface OAuthInitResult {
  authorizationUrl: string;
  state: string;
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
  scope: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  avatarUrl: string;
  email?: string;
  name?: string;
}

export interface GitHubConnection {
  id: string;
  userId: string;
  githubUserId: number;
  githubUsername: string;
  githubAvatarUrl?: string;
  githubEmail?: string;
  status: 'active' | 'expired' | 'revoked';
  tokenScope: string;
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface GitHubConnectionRow {
  [key: string]: unknown;
  id: string;
  user_id: string;
  github_user_id: number;
  github_username: string;
  github_avatar_url: string | null;
  github_email: string | null;
  access_token_encrypted: string;
  access_token_iv: string;
  access_token_tag: string;
  refresh_token_encrypted: string | null;
  refresh_token_iv: string | null;
  refresh_token_tag: string | null;
  token_expires_at: Date | null;
  token_scope: string;
  status: 'active' | 'expired' | 'revoked';
  last_used_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

// ============================================================================
// Token Encryption Types (SEC-001)
// ============================================================================

export interface EncryptedData {
  ciphertext: string;   // Base64 encoded
  iv: string;           // Base64 encoded (12 bytes for GCM)
  tag: string;          // Base64 encoded (16 bytes)
}

export interface EncryptedTokenSet {
  accessToken: EncryptedData;
  refreshToken: EncryptedData | null;
  expiresAt: Date | null;
  scope: string;
}

// ============================================================================
// OAuth State Types (GH-002)
// ============================================================================

export interface OAuthState {
  id: string;
  userId: string;
  stateToken: string;
  redirectUri?: string;
  expiresAt: Date;
  used: boolean;
  createdAt: Date;
}

export interface OAuthStateRow {
  [key: string]: unknown;
  id: string;
  user_id: string;
  state_token: string;
  redirect_uri: string | null;
  expires_at: Date;
  used: boolean;
  created_at: Date;
}

// ============================================================================
// Repository Types (GH-011, GH-012, GH-020)
// ============================================================================

export interface GitHubRepository {
  id: number;
  owner: string;
  name: string;
  fullName: string;
  description?: string;
  defaultBranch: string;
  isPrivate: boolean;
  htmlUrl: string;
  cloneUrl: string;
  size: number;
  language?: string;
  pushedAt?: Date;
}

export interface ConnectedRepository {
  id: string;
  connectionId: string;
  userId: string;
  projectId?: string;
  githubRepoId: number;
  owner: string;
  name: string;
  fullName: string;
  description?: string;
  defaultBranch: string;
  isPrivate: boolean;
  htmlUrl: string;
  cloneUrl: string;
  webhookId?: number;
  webhookActive: boolean;
  autoScanEnabled: boolean;
  scanOnPush: boolean;
  scanOnPr: boolean;
  scanProfile: string;
  lastScannedAt?: Date;
  lastScannedCommit?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConnectedRepositoryRow {
  [key: string]: unknown;
  id: string;
  connection_id: string;
  user_id: string;
  project_id: string | null;
  github_repo_id: number;
  owner: string;
  name: string;
  full_name: string;
  description: string | null;
  default_branch: string;
  is_private: boolean;
  html_url: string;
  clone_url: string;
  webhook_id: number | null;
  webhook_secret_encrypted: string | null;
  webhook_secret_iv: string | null;
  webhook_secret_tag: string | null;
  webhook_active: boolean;
  auto_scan_enabled: boolean;
  scan_on_push: boolean;
  scan_on_pr: boolean;
  scan_profile: string;
  last_scan_id: string | null;
  last_scanned_at: Date | null;
  last_scanned_commit: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface GitHubOrganization {
  login: string;
  avatarUrl: string;
}

// ============================================================================
// Clone Types (GH-031, GH-032, SEC-008, SEC-009)
// ============================================================================

export interface CloneOptions {
  branch?: string;
  depth?: number;          // Shallow clone depth
  sparse?: string[];       // Sparse checkout paths
  timeout?: number;        // Clone timeout in ms
}

export interface CloneResult {
  localPath: string;
  commit: string;
  branch: string;
  cloneId: string;         // Unique ID for cleanup
}

export interface CleanupRecord {
  cloneId: string;
  path: string;
  createdAt: Date;
  expiresAt: Date;
}

// ============================================================================
// Webhook Types (GH-021 to GH-023, SEC-005)
// ============================================================================

export interface WebhookPayload {
  action?: string;
  sender: {
    login: string;
    id: number;
  };
  repository: {
    id: number;
    full_name: string;
    default_branch: string;
  };
  // Push event specific
  ref?: string;
  before?: string;
  after?: string;
  commits?: Array<{
    id: string;
    message: string;
    author: { name: string; email: string };
  }>;
  // Pull request specific
  pull_request?: {
    number: number;
    title: string;
    head: { sha: string; ref: string };
    base: { sha: string; ref: string };
  };
}

export interface WebhookEvent {
  id: string;
  repositoryId: string;
  deliveryId: string;
  eventType: string;
  action?: string;
  senderLogin: string;
  senderId: number;
  ref?: string;
  beforeSha?: string;
  afterSha?: string;
  processed: boolean;
  scanId?: string;
  error?: string;
  receivedAt: Date;
  processedAt?: Date;
}

export interface WebhookEventRow {
  [key: string]: unknown;
  id: string;
  repository_id: string;
  event_type: string;
  delivery_id: string;
  action: string | null;
  sender_login: string;
  sender_id: number;
  ref: string | null;
  before_sha: string | null;
  after_sha: string | null;
  processed: boolean;
  scan_id: string | null;
  error: string | null;
  received_at: Date;
  processed_at: Date | null;
}

export interface WebhookConfig {
  url: string;
  secret: string;
  events: string[];
}

// ============================================================================
// SSRF Validation Types (security-h003)
// ============================================================================

export interface SSRFValidationResult {
  valid: boolean;
  error?: string;
}

// ============================================================================
// Rate Limiting Types (security-h001)
// ============================================================================

export interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
}

export interface BackoffResult {
  blocked: boolean;
  waitSeconds?: number;
}

// ============================================================================
// Webhook Deduplication Types (security-h002)
// ============================================================================

export interface DeliveryCheckResult {
  isDuplicate: boolean;
  firstSeenAt?: Date;
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface ConnectRepositoryRequest {
  connectionId: string;
  repoFullName: string;
  projectId: string;
  autoScan?: boolean;
  scanOnPush?: boolean;
  scanOnPr?: boolean;
  scanProfile?: string;
}

export interface TriggerScanRequest {
  branch?: string;
  profile?: string;
}

export interface ListRepositoriesQuery {
  connectionId: string;
  page?: number;
  perPage?: number;
  type?: 'all' | 'owner' | 'member';
  sort?: 'created' | 'updated' | 'pushed' | 'full_name';
  direction?: 'asc' | 'desc';
}

export interface ListOrgRepositoriesQuery {
  connectionId: string;
  org: string;
  page?: number;
  perPage?: number;
  type?: 'all' | 'public' | 'private' | 'forks' | 'sources' | 'member';
}

// ============================================================================
// Scan Job Data Types
// ============================================================================

export interface GitHubScanJobData {
  repositoryId: string;
  connectionId: string;
  repoFullName: string;
  branch: string;
  commit: string;
  trigger: 'push' | 'pull_request' | 'manual';
  profile: string;
  prNumber?: number;
  prTitle?: string;
}
