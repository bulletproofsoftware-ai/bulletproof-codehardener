-- Code Hardener Database Schema
-- PostgreSQL 16+
-- Single Postgres instance, 3 databases: codehardener (default), defectdojo, n8n
-- This file represents the final schema state including all migrations (001-018).

-- Create additional databases for DefectDojo and n8n
-- Note: These run in the default 'codehardener' database context during init
-- The actual DB creation happens via Docker entrypoint or init scripts
SELECT 'CREATE DATABASE defectdojo' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'defectdojo')\gexec
SELECT 'CREATE DATABASE n8n' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'n8n')\gexec

-- Extensions (for codehardener database)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Users table
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255),
    avatar_url VARCHAR(500),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- OAuth providers
-- ============================================================================
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_account_id)
);

-- ============================================================================
-- Projects
-- ============================================================================
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    repo_url VARCHAR(500),
    repo_provider VARCHAR(50),
    default_branch VARCHAR(100) DEFAULT 'main',
    is_active BOOLEAN DEFAULT TRUE,
    last_scan_id UUID,                                  -- from 007
    last_scan_at TIMESTAMP WITH TIME ZONE,              -- from 007
    last_score INTEGER,                                 -- from 007
    defectdojo_product_id INTEGER,                      -- from 005
    target_url TEXT,                                     -- from 016
    container_image TEXT,                                -- from 016
    openapi_spec_path TEXT,                              -- from 016
    auth_config JSONB,                                   -- from 016
    registry_credentials_id UUID,                        -- from 016
    llm_analysis_enabled BOOLEAN NOT NULL DEFAULT FALSE, -- from 023 (privacy opt-in)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Scans
-- ============================================================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending',
    score INTEGER,
    score_raw INTEGER,                                  -- from 010
    quality_level VARCHAR(20),
    findings_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}',
    commit_sha VARCHAR(40),
    branch VARCHAR(100),
    profile VARCHAR(50) DEFAULT 'standard',             -- from 007
    duration INTEGER,
    trigger_type VARCHAR(50) DEFAULT 'manual',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    defectdojo_engagement_id INTEGER,                   -- from 005
    n8n_execution_id VARCHAR(255),                      -- from 005
    scanners_executed JSONB DEFAULT '[]',               -- from 007
    code_analysis_summary JSONB,                        -- from 012
    mutation_score NUMERIC(5,2),                        -- from 011
    license_risk_count INTEGER DEFAULT 0,               -- from 011
    hallucinated_package_count INTEGER DEFAULT 0,       -- from 011
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add FK from projects.last_scan_id now that scans table exists
ALTER TABLE projects ADD CONSTRAINT fk_projects_last_scan
    FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL;

-- ============================================================================
-- Findings
-- Columns widened to TEXT per migration 009 to prevent truncation
-- ============================================================================
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,  -- from 007
    scanner TEXT,                                       -- widened in 009
    severity TEXT NOT NULL,                             -- widened in 009
    title TEXT NOT NULL,                                -- widened in 009
    description TEXT,
    description_simple TEXT,
    file_path TEXT,                                     -- widened in 009
    line_number INTEGER,
    column_number INTEGER,
    end_line INTEGER,
    end_column INTEGER,
    code_snippet TEXT,
    cwe_id TEXT,                                       -- widened in 009
    owasp_category TEXT,                               -- widened in 009
    tool_name TEXT,                                    -- widened in 009
    rule_id TEXT,                                      -- widened in 009
    fix_available BOOLEAN DEFAULT FALSE,
    fix_code TEXT,
    fix_description TEXT,
    status TEXT DEFAULT 'open',                        -- widened in 009
    metadata JSONB DEFAULT '{}',                       -- from 007
    dismissed_reason TEXT,
    dismissed_comment TEXT,                             -- from 006
    dismissed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    dismissed_at TIMESTAMP WITH TIME ZONE,
    exploitability VARCHAR(20),                        -- from 012
    reachable BOOLEAN,                                 -- from 012
    dataflow_match VARCHAR(20),                        -- from 012
    llm_verified BOOLEAN,                              -- from 012
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()  -- from 013
);

-- ============================================================================
-- Finding Suppressions (from 010)
-- ============================================================================
CREATE TABLE finding_suppressions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    match_type VARCHAR(50) NOT NULL,
    match_value TEXT NOT NULL,
    target_status VARCHAR(50) NOT NULL DEFAULT 'deferred',
    reason TEXT,
    comment TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Attestations
-- ============================================================================
CREATE TABLE attestations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    attestation_type VARCHAR(255) DEFAULT 'https://codehardener.com/scan/v1',
    subject_name VARCHAR(255),
    subject_digest VARCHAR(100),
    predicate JSONB,
    signature TEXT,
    signature_algorithm VARCHAR(50) DEFAULT 'ECDSA-P256',
    certificate TEXT,
    certificate_chain TEXT,
    rekor_log_id VARCHAR(255),
    rekor_log_index BIGINT,
    transparency_log_url VARCHAR(500),
    attestation_json JSONB,
    predicate_type VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- API Keys
-- ============================================================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    permissions JSONB DEFAULT '["read"]',
    rate_limit INTEGER DEFAULT 1000,
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip VARCHAR(45),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Policies
-- ============================================================================
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(20) DEFAULT 'yaml',
    policy_content TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    severity_threshold VARCHAR(20) DEFAULT 'high',
    auto_fail BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Policy Rules (for structured policies)
-- ============================================================================
CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    rule_type VARCHAR(100) NOT NULL,
    condition JSONB NOT NULL,
    action VARCHAR(50) DEFAULT 'warn',
    message TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    order_index INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Webhooks (extended in 002)
-- ============================================================================
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,  -- from 002
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    secret VARCHAR(255),
    events JSONB DEFAULT '["scan.completed", "finding.critical"]',
    headers JSONB DEFAULT '{}',                         -- from 002
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMP WITH TIME ZONE,
    last_status_code INTEGER,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Webhook Deliveries (extended in 002)
-- event_type renamed to event in migration 002
-- ============================================================================
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    event VARCHAR(100) NOT NULL,                        -- renamed from event_type in 002
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    response_time_ms INTEGER,
    attempts INTEGER DEFAULT 1,                         -- from 002
    success BOOLEAN DEFAULT FALSE,                      -- from 002
    next_retry_at TIMESTAMP WITH TIME ZONE,             -- from 002
    error_message TEXT,                                 -- from 002
    delivered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()   -- from 002
);

-- ============================================================================
-- Reports (extended in 007)
-- ============================================================================
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) DEFAULT 'pdf',
    title VARCHAR(255),
    description TEXT,
    file_url VARCHAR(500),
    file_size INTEGER,
    report_content TEXT,                                -- from 007
    content_type VARCHAR(50) DEFAULT 'application/json', -- from 007
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Badges (updated in 007)
-- ============================================================================
CREATE TABLE badges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    type VARCHAR(50) DEFAULT 'score',
    style VARCHAR(20) DEFAULT 'flat',
    label VARCHAR(100),
    config JSONB DEFAULT '{}',
    token VARCHAR(64) UNIQUE NOT NULL,
    is_public BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Integrations
-- ============================================================================
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    name VARCHAR(255),
    config JSONB DEFAULT '{}',
    credentials_encrypted TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_synced_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Teams (from 007)
-- ============================================================================
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL DEFAULT 'My Team',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Team Members (extended in 007)
-- ============================================================================
CREATE TABLE team_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    status VARCHAR(20) DEFAULT 'active',                -- from 007
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()   -- from 007
);

-- ============================================================================
-- Team Invites (from 007)
-- ============================================================================
CREATE TABLE team_invites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'member',
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Notifications (from 007)
-- ============================================================================
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    message TEXT,
    link VARCHAR(500),
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Notification Preferences (from 007)
-- ============================================================================
CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Subscriptions (from 007)
-- ============================================================================
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    plan_id VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    stripe_subscription_id VARCHAR(255),
    stripe_customer_id VARCHAR(255),
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    seats INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Invoices (from 007)
-- ============================================================================
CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
    stripe_invoice_id VARCHAR(255),
    amount INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(3) DEFAULT 'usd',
    status VARCHAR(20) NOT NULL DEFAULT 'paid',
    description TEXT,
    invoice_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Payment Methods (from 007)
-- ============================================================================
CREATE TABLE payment_methods (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    stripe_payment_method_id VARCHAR(255),
    type VARCHAR(20) DEFAULT 'card',
    last4 VARCHAR(4),
    brand VARCHAR(50),
    exp_month INTEGER,
    exp_year INTEGER,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- Session tokens (for refresh tokens)
-- ============================================================================
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    device_info JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- Code Analysis Results (from 003)
-- ============================================================================
CREATE TABLE code_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repository_url TEXT,
    analysis_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    detected_languages JSONB NOT NULL DEFAULT '[]',
    detected_frameworks JSONB NOT NULL DEFAULT '[]',
    extracted_endpoints JSONB NOT NULL DEFAULT '[]',
    auth_patterns JSONB NOT NULL DEFAULT '[]',
    data_flows JSONB NOT NULL DEFAULT '[]',
    sensitive_data_points JSONB NOT NULL DEFAULT '[]',
    dependencies JSONB NOT NULL DEFAULT '[]',
    infrastructure_files JSONB NOT NULL DEFAULT '[]',
    code_summary JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    processing_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- BRD Analysis Results (from 003)
-- ============================================================================
CREATE TABLE brd_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    document_name TEXT NOT NULL,
    document_type VARCHAR(20) NOT NULL,
    analysis_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    requirements JSONB NOT NULL DEFAULT '[]',
    security_requirements JSONB NOT NULL DEFAULT '[]',
    functional_requirements JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Generated Test Cases (from 003)
-- ============================================================================
CREATE TABLE generated_test_cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    code_analysis_id UUID REFERENCES code_analysis_results(id) ON DELETE SET NULL,
    brd_analysis_id UUID REFERENCES brd_analysis_results(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    owasp_category VARCHAR(20),
    cwe_id INTEGER,
    aligned_requirement_id TEXT,
    alignment_confidence DECIMAL(3,2),
    test_prompt TEXT NOT NULL,
    target_file TEXT,
    target_endpoint TEXT,
    target_function TEXT,
    recommended_scanners JSONB NOT NULL DEFAULT '[]',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    expected_severity VARCHAR(20),
    executed BOOLEAN DEFAULT FALSE,
    execution_date TIMESTAMP WITH TIME ZONE,
    scan_result_id UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- GitHub Connections (from 004)
-- ============================================================================
CREATE TABLE github_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_user_id BIGINT NOT NULL,
    github_username VARCHAR(255) NOT NULL,
    github_avatar_url TEXT,
    github_email VARCHAR(255),
    access_token_encrypted TEXT NOT NULL,
    access_token_iv VARCHAR(24) NOT NULL,
    access_token_tag VARCHAR(24) NOT NULL,
    refresh_token_encrypted TEXT,
    refresh_token_iv VARCHAR(24),
    refresh_token_tag VARCHAR(24),
    token_expires_at TIMESTAMPTZ,
    token_scope TEXT NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, github_user_id)
);

-- ============================================================================
-- GitHub OAuth States (from 004)
-- ============================================================================
CREATE TABLE github_oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state_token VARCHAR(128) NOT NULL UNIQUE,
    redirect_uri TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- GitHub Repositories (from 004)
-- ============================================================================
CREATE TABLE github_repositories (
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
    webhook_id BIGINT,
    webhook_secret_encrypted TEXT,
    webhook_secret_iv VARCHAR(24),
    webhook_secret_tag VARCHAR(24),
    webhook_active BOOLEAN NOT NULL DEFAULT false,
    auto_scan_enabled BOOLEAN NOT NULL DEFAULT true,
    scan_on_push BOOLEAN NOT NULL DEFAULT true,
    scan_on_pr BOOLEAN NOT NULL DEFAULT true,
    scan_profile VARCHAR(100) NOT NULL DEFAULT 'standard',
    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_scanned_at TIMESTAMPTZ,
    last_scanned_commit VARCHAR(40),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(connection_id, github_repo_id)
);

-- ============================================================================
-- GitHub Webhook Events (from 004)
-- ============================================================================
CREATE TABLE github_webhook_events (
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

-- ============================================================================
-- Registry Credentials (from 016)
-- ============================================================================
CREATE TABLE registry_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    registry TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    password_iv VARCHAR(24) NOT NULL,
    password_tag VARCHAR(24) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add FK and constraints now that registry_credentials table exists
ALTER TABLE projects ADD CONSTRAINT fk_projects_registry_credentials
    FOREIGN KEY (registry_credentials_id) REFERENCES registry_credentials(id) ON DELETE SET NULL;

ALTER TABLE projects ADD CONSTRAINT chk_auth_config_password_encrypted
    CHECK (auth_config IS NULL OR (auth_config->'password' IS NOT NULL AND jsonb_typeof(auth_config->'password') = 'object'));

COMMENT ON COLUMN projects.auth_config IS 'DAST authentication config. password field is always {encrypted, iv, tag}, never plaintext.';

-- ============================================================================
-- CHECK constraints on enum-like columns (from 018)
-- ============================================================================
ALTER TABLE findings ADD CONSTRAINT chk_findings_status
    CHECK (status IN ('open', 'fixed', 'ignored', 'false_positive', 'deferred'));
ALTER TABLE findings ADD CONSTRAINT chk_findings_severity
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
ALTER TABLE findings ADD CONSTRAINT chk_findings_exploitability
    CHECK (exploitability IS NULL OR exploitability IN ('confirmed', 'likely', 'theoretical', 'unlikely'));
ALTER TABLE findings ADD CONSTRAINT chk_findings_dataflow
    CHECK (dataflow_match IS NULL OR dataflow_match IN ('direct', 'indirect', 'sanitized', 'none'));
ALTER TABLE scans ADD CONSTRAINT chk_scans_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'));

-- ============================================================================
-- OAuth Audit Log (from 008)
-- ============================================================================
CREATE TABLE oauth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    result VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failure')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Indexes for performance
-- ============================================================================

-- Users
CREATE INDEX idx_users_email ON users(email);

-- OAuth accounts
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_accounts_provider ON oauth_accounts(provider, provider_account_id);

-- Projects
CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE INDEX idx_projects_name ON projects(user_id, name);
CREATE INDEX idx_projects_dd_product ON projects(defectdojo_product_id) WHERE defectdojo_product_id IS NOT NULL;

-- Scans
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_dd_engagement ON scans(defectdojo_engagement_id) WHERE defectdojo_engagement_id IS NOT NULL;

-- Findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_project_id ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);
CREATE INDEX idx_findings_dismissed ON findings(status, dismissed_at) WHERE status = 'dismissed';
CREATE INDEX idx_findings_exploitability ON findings(exploitability);
CREATE INDEX idx_findings_reachable ON findings(reachable);

-- Prevent duplicate findings within the same scan (from 014)
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique_per_scan
ON findings (scan_id, scanner, COALESCE(rule_id, ''), title, COALESCE(file_path, ''), COALESCE(line_number, 0));

-- Finding Suppressions
CREATE INDEX idx_suppressions_project ON finding_suppressions(project_id);
CREATE INDEX idx_suppressions_active ON finding_suppressions(project_id, is_active) WHERE is_active = TRUE;

-- Attestations
CREATE INDEX idx_attestations_scan_id ON attestations(scan_id);
CREATE INDEX idx_attestations_rekor ON attestations(rekor_log_id);

-- API Keys
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- Policies
CREATE INDEX idx_policies_user_id ON policies(user_id);

-- Webhooks
CREATE INDEX idx_webhooks_user_id ON webhooks(user_id);
CREATE INDEX idx_webhooks_project_id ON webhooks(project_id);

-- Webhook deliveries
CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_success ON webhook_deliveries(success);
CREATE INDEX idx_webhook_deliveries_created_at ON webhook_deliveries(created_at DESC);
CREATE INDEX idx_webhook_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE next_retry_at IS NOT NULL AND success = FALSE;

-- Reports
CREATE INDEX idx_reports_user_id ON reports(user_id);
CREATE INDEX idx_reports_project_id ON reports(project_id);

-- Badges
CREATE INDEX idx_badges_project_id ON badges(project_id);
CREATE INDEX idx_badges_token ON badges(token);
CREATE INDEX idx_badges_user_id ON badges(user_id);

-- Integrations
CREATE INDEX idx_integrations_user_id ON integrations(user_id);

-- Teams
CREATE INDEX idx_team_members_team_id ON team_members(team_id);
CREATE INDEX idx_team_members_user_id ON team_members(user_id);
CREATE INDEX idx_team_invites_team_id ON team_invites(team_id);
CREATE INDEX idx_team_invites_token ON team_invites(token);

-- Notifications
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_unread ON notifications(user_id, read) WHERE read = FALSE;

-- Subscriptions
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

-- Invoices
CREATE INDEX idx_invoices_user_id ON invoices(user_id);

-- Payment Methods
CREATE INDEX idx_payment_methods_user_id ON payment_methods(user_id);

-- Audit Log
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);

-- Refresh Tokens
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- Code Analysis (from 003)
CREATE INDEX idx_code_analysis_project ON code_analysis_results(project_id);
CREATE INDEX idx_code_analysis_status ON code_analysis_results(status);
CREATE INDEX idx_code_analysis_created_at ON code_analysis_results(created_at DESC);

-- BRD Analysis (from 003)
CREATE INDEX idx_brd_analysis_project ON brd_analysis_results(project_id);
CREATE INDEX idx_brd_analysis_status ON brd_analysis_results(status);
CREATE INDEX idx_brd_analysis_created_at ON brd_analysis_results(created_at DESC);

-- Generated Test Cases (from 003)
CREATE INDEX idx_test_cases_project ON generated_test_cases(project_id);
CREATE INDEX idx_test_cases_category ON generated_test_cases(category);
CREATE INDEX idx_test_cases_owasp ON generated_test_cases(owasp_category);
CREATE INDEX idx_test_cases_cwe ON generated_test_cases(cwe_id);
CREATE INDEX idx_test_cases_priority ON generated_test_cases(priority);
CREATE INDEX idx_test_cases_executed ON generated_test_cases(executed);
CREATE INDEX idx_test_cases_code_analysis ON generated_test_cases(code_analysis_id);
CREATE INDEX idx_test_cases_brd_analysis ON generated_test_cases(brd_analysis_id);
CREATE INDEX idx_test_cases_requirement ON generated_test_cases(aligned_requirement_id);
CREATE INDEX idx_test_cases_created_at ON generated_test_cases(created_at DESC);

-- GitHub Connections (from 004)
CREATE INDEX idx_github_connections_user_id ON github_connections(user_id);
CREATE INDEX idx_github_connections_github_user_id ON github_connections(github_user_id);
CREATE INDEX idx_github_connections_status ON github_connections(status);

-- GitHub OAuth States (from 004)
CREATE INDEX idx_github_oauth_states_state_token ON github_oauth_states(state_token);
CREATE INDEX idx_github_oauth_states_user_id ON github_oauth_states(user_id);
CREATE INDEX idx_github_oauth_states_expires_at ON github_oauth_states(expires_at);

-- GitHub Repositories (from 004)
CREATE INDEX idx_github_repositories_user_id ON github_repositories(user_id);
CREATE INDEX idx_github_repositories_connection_id ON github_repositories(connection_id);
CREATE INDEX idx_github_repositories_project_id ON github_repositories(project_id);
CREATE INDEX idx_github_repositories_github_repo_id ON github_repositories(github_repo_id);
CREATE INDEX idx_github_repositories_full_name ON github_repositories(full_name);

-- GitHub Webhook Events (from 004)
CREATE INDEX idx_github_webhook_events_repository_id ON github_webhook_events(repository_id);
CREATE INDEX idx_github_webhook_events_delivery_id ON github_webhook_events(delivery_id);
CREATE INDEX idx_github_webhook_events_event_type ON github_webhook_events(event_type);
CREATE INDEX idx_github_webhook_events_processed ON github_webhook_events(processed);
CREATE INDEX idx_github_webhook_events_received_at ON github_webhook_events(received_at);

-- OAuth Audit Log (from 008)
CREATE INDEX idx_oauth_audit_user_id ON oauth_audit_log(user_id);
CREATE INDEX idx_oauth_audit_timestamp ON oauth_audit_log(timestamp);
CREATE INDEX idx_oauth_audit_event_type ON oauth_audit_log(event_type);
CREATE INDEX idx_oauth_audit_result ON oauth_audit_log(result);
CREATE INDEX idx_oauth_audit_user_timestamp ON oauth_audit_log(user_id, timestamp DESC);

-- Registry Credentials (from 016)
CREATE INDEX idx_registry_credentials_user ON registry_credentials (user_id);
CREATE INDEX idx_projects_target_url ON projects (target_url) WHERE target_url IS NOT NULL;

-- Composite indexes for common query patterns (from 018)
CREATE INDEX idx_findings_scan_status ON findings(scan_id, status);
CREATE INDEX idx_findings_project_status_severity ON findings(project_id, status, severity);
CREATE INDEX idx_scans_project_status_created ON scans(project_id, status, created_at DESC);
CREATE INDEX idx_findings_tool_name ON findings(tool_name) WHERE tool_name IS NOT NULL;

-- ============================================================================
-- Updated_at trigger function
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- ============================================================================
-- Apply updated_at triggers
-- ============================================================================
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_webhooks_updated_at BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_finding_suppressions_updated_at BEFORE UPDATE ON finding_suppressions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_code_analysis_results_updated_at BEFORE UPDATE ON code_analysis_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_brd_analysis_results_updated_at BEFORE UPDATE ON brd_analysis_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_generated_test_cases_updated_at BEFORE UPDATE ON generated_test_cases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- GitHub tables use their own trigger function (from 004)
CREATE OR REPLACE FUNCTION update_github_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER github_connections_updated_at BEFORE UPDATE ON github_connections
    FOR EACH ROW EXECUTE FUNCTION update_github_updated_at();

CREATE TRIGGER github_repositories_updated_at BEFORE UPDATE ON github_repositories
    FOR EACH ROW EXECUTE FUNCTION update_github_updated_at();

CREATE TRIGGER update_registry_credentials_updated_at BEFORE UPDATE ON registry_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Missing updated_at triggers (from 018)
CREATE TRIGGER update_badges_updated_at BEFORE UPDATE ON badges
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_teams_updated_at BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_team_members_updated_at BEFORE UPDATE ON team_members
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notifications_updated_at BEFORE UPDATE ON notifications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_preferences_updated_at BEFORE UPDATE ON notification_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Comments (from 003 and 004)
-- ============================================================================
COMMENT ON TABLE code_analysis_results IS 'Stores code repository analysis results from CA-001 to CA-010 modules';
COMMENT ON TABLE brd_analysis_results IS 'Stores parsed BRD document results from BP-001 to BP-003 modules';
COMMENT ON TABLE generated_test_cases IS 'Stores generated test cases from TG-001 to TG-003 modules';

COMMENT ON TABLE github_connections IS 'Stores GitHub OAuth connections with encrypted tokens';
COMMENT ON TABLE github_oauth_states IS 'Temporary OAuth state tokens for CSRF protection';
COMMENT ON TABLE github_repositories IS 'Connected GitHub repositories for scanning';
COMMENT ON TABLE github_webhook_events IS 'Received webhook events from GitHub';

COMMENT ON TABLE oauth_audit_log IS 'Audit log for OAuth token operations (SEC-026). Minimum 90-day retention.';

-- ============================================================================
-- LLM Assurance Scanners (from 023)
-- defending-code-reference-harness integration. PK/FK columns are UUID to match
-- projects.id / findings.id; free-text columns are TEXT per project convention.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,                       -- THREAT_MODEL.md markdown (harness schema.md contract)
    threats_json TEXT NOT NULL DEFAULT '[]',     -- parsed section 4 threats table (JSON array)
    source_inventory_hash TEXT NOT NULL,         -- staleness detection
    model_used TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS candidate_patches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    -- A5: scan_id is a real FK so patches cascade-delete with their scan.
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    patch_diff TEXT NOT NULL,
    rationale TEXT NOT NULL,
    validation_notes TEXT NOT NULL,              -- build / exploit-path-closed / tests / bypass checklist (LLM self-assessment)
    model_used TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'accepted', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- F4: retry idempotency — BullMQ attempts:3 re-runs the patch stage, which
    -- re-INSERTs the same (finding_id, scan_id). The unique constraint backs the
    -- ON CONFLICT (finding_id, scan_id) DO NOTHING in insertPatch (llm-patch.ts).
    CONSTRAINT uq_candidate_patches_finding_scan UNIQUE (finding_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_candidate_patches_finding ON candidate_patches(finding_id);
CREATE INDEX IF NOT EXISTS idx_candidate_patches_scan ON candidate_patches(scan_id);

COMMENT ON TABLE threat_models IS 'Persistent per-project LLM-generated threat model (defending-code-reference-harness bootstrap)';
COMMENT ON TABLE candidate_patches IS 'LLM-proposed candidate fixes for verified findings; status is metadata only, never auto-applied';
COMMENT ON COLUMN projects.llm_analysis_enabled IS 'Privacy opt-in: when TRUE, project source may be transmitted to Anthropic for LLM assurance scanning';

-- ============================================================================
-- Schema Migrations tracking (from 018)
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO schema_migrations (version, name) VALUES
    ('001', 'init_schema'),
    ('002', 'webhook_dispatcher'),
    ('003', 'test_generator'),
    ('004', 'github_integration'),
    ('005', 'defectdojo_integration'),
    ('006', 'findings_dismissed_comment'),
    ('007', 'combined_schema'),
    ('008', 'oauth_audit_log'),
    ('009', 'varchar_to_text'),
    ('010', 'dual_scoring'),
    ('011', 'ai_code_quality'),
    ('012', 'finding_enrichment'),
    ('013', 'findings_updated_at'),
    ('014', 'dedup_findings'),
    ('015', 'quality_terminology'),
    ('016', 'project_scan_context'),
    ('017', 'fix_fk_constraints'),
    ('018', 'database_hardening'),
    ('023', 'llm_assurance_scanners')
ON CONFLICT (version) DO NOTHING;
