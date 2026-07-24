-- GitHub Integration Migration
-- Creates tables for OAuth connections, repositories, and webhook events

-- ============================================================================
-- GitHub Connections (OAuth tokens)
-- ============================================================================
CREATE TABLE IF NOT EXISTS github_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_user_id BIGINT NOT NULL,
    github_username VARCHAR(255) NOT NULL,
    github_avatar_url TEXT,
    github_email VARCHAR(255),

    -- Encrypted token storage (AES-256-GCM)
    access_token_encrypted TEXT NOT NULL,
    access_token_iv VARCHAR(24) NOT NULL,  -- Base64 encoded 12-byte IV
    access_token_tag VARCHAR(24) NOT NULL, -- Base64 encoded 16-byte tag

    refresh_token_encrypted TEXT,
    refresh_token_iv VARCHAR(24),
    refresh_token_tag VARCHAR(24),

    token_expires_at TIMESTAMPTZ,
    token_scope TEXT NOT NULL DEFAULT '',

    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    last_used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each GitHub account can only be connected once per user
    UNIQUE(user_id, github_user_id)
);

-- Indexes for github_connections
CREATE INDEX IF NOT EXISTS idx_github_connections_user_id ON github_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_github_connections_github_user_id ON github_connections(github_user_id);
CREATE INDEX IF NOT EXISTS idx_github_connections_status ON github_connections(status);

-- ============================================================================
-- GitHub OAuth States (CSRF protection)
-- ============================================================================
CREATE TABLE IF NOT EXISTS github_oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state_token VARCHAR(128) NOT NULL UNIQUE,
    redirect_uri TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for github_oauth_states
CREATE INDEX IF NOT EXISTS idx_github_oauth_states_state_token ON github_oauth_states(state_token);
CREATE INDEX IF NOT EXISTS idx_github_oauth_states_user_id ON github_oauth_states(user_id);
CREATE INDEX IF NOT EXISTS idx_github_oauth_states_expires_at ON github_oauth_states(expires_at);

-- ============================================================================
-- Connected Repositories
-- ============================================================================
CREATE TABLE IF NOT EXISTS github_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES github_connections(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,

    github_repo_id BIGINT NOT NULL,
    owner VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    full_name VARCHAR(512) NOT NULL,
    description TEXT,
    default_branch VARCHAR(255) NOT NULL DEFAULT 'main',
    is_private BOOLEAN NOT NULL DEFAULT false,
    html_url TEXT NOT NULL,
    clone_url TEXT NOT NULL,

    -- Webhook configuration
    webhook_id BIGINT,
    webhook_secret_encrypted TEXT,
    webhook_secret_iv VARCHAR(24),
    webhook_secret_tag VARCHAR(24),
    webhook_active BOOLEAN NOT NULL DEFAULT false,

    -- Scanning configuration
    auto_scan_enabled BOOLEAN NOT NULL DEFAULT true,
    scan_on_push BOOLEAN NOT NULL DEFAULT true,
    scan_on_pr BOOLEAN NOT NULL DEFAULT true,
    scan_profile VARCHAR(100) NOT NULL DEFAULT 'standard',

    -- Last scan tracking
    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_scanned_at TIMESTAMPTZ,
    last_scanned_commit VARCHAR(40),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each GitHub repo can only be connected once per connection
    UNIQUE(connection_id, github_repo_id)
);

-- Indexes for github_repositories
CREATE INDEX IF NOT EXISTS idx_github_repositories_user_id ON github_repositories(user_id);
CREATE INDEX IF NOT EXISTS idx_github_repositories_connection_id ON github_repositories(connection_id);
CREATE INDEX IF NOT EXISTS idx_github_repositories_project_id ON github_repositories(project_id);
CREATE INDEX IF NOT EXISTS idx_github_repositories_github_repo_id ON github_repositories(github_repo_id);
CREATE INDEX IF NOT EXISTS idx_github_repositories_full_name ON github_repositories(full_name);

-- ============================================================================
-- Webhook Events
-- ============================================================================
CREATE TABLE IF NOT EXISTS github_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES github_repositories(id) ON DELETE CASCADE,

    event_type VARCHAR(50) NOT NULL,
    delivery_id VARCHAR(100) NOT NULL UNIQUE,
    action VARCHAR(50),

    sender_login VARCHAR(255) NOT NULL,
    sender_id BIGINT NOT NULL,

    ref VARCHAR(255),
    before_sha VARCHAR(40),
    after_sha VARCHAR(40),

    processed BOOLEAN NOT NULL DEFAULT false,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    error TEXT,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- Indexes for github_webhook_events
CREATE INDEX IF NOT EXISTS idx_github_webhook_events_repository_id ON github_webhook_events(repository_id);
CREATE INDEX IF NOT EXISTS idx_github_webhook_events_delivery_id ON github_webhook_events(delivery_id);
CREATE INDEX IF NOT EXISTS idx_github_webhook_events_event_type ON github_webhook_events(event_type);
CREATE INDEX IF NOT EXISTS idx_github_webhook_events_processed ON github_webhook_events(processed);
CREATE INDEX IF NOT EXISTS idx_github_webhook_events_received_at ON github_webhook_events(received_at);

-- ============================================================================
-- Trigger for updated_at
-- ============================================================================
CREATE OR REPLACE FUNCTION update_github_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers
DROP TRIGGER IF EXISTS github_connections_updated_at ON github_connections;
CREATE TRIGGER github_connections_updated_at
    BEFORE UPDATE ON github_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_github_updated_at();

DROP TRIGGER IF EXISTS github_repositories_updated_at ON github_repositories;
CREATE TRIGGER github_repositories_updated_at
    BEFORE UPDATE ON github_repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_github_updated_at();

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE github_connections IS 'Stores GitHub OAuth connections with encrypted tokens';
COMMENT ON TABLE github_oauth_states IS 'Temporary OAuth state tokens for CSRF protection';
COMMENT ON TABLE github_repositories IS 'Connected GitHub repositories for scanning';
COMMENT ON TABLE github_webhook_events IS 'Received webhook events from GitHub';

COMMENT ON COLUMN github_connections.access_token_encrypted IS 'AES-256-GCM encrypted access token (base64)';
COMMENT ON COLUMN github_connections.access_token_iv IS 'Base64 encoded 12-byte initialization vector';
COMMENT ON COLUMN github_connections.access_token_tag IS 'Base64 encoded 16-byte authentication tag';

COMMENT ON COLUMN github_repositories.webhook_secret_encrypted IS 'AES-256-GCM encrypted webhook secret';
COMMENT ON COLUMN github_repositories.scan_profile IS 'Scan configuration profile name';

COMMENT ON COLUMN github_webhook_events.delivery_id IS 'GitHub X-GitHub-Delivery header - unique per delivery';
