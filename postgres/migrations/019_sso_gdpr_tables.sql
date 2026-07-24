-- Migration 019: Add SSO and GDPR processing tables
-- Required by: backend/src/services/sso/saml.service.ts, backend/src/services/gdpr/data-subject.service.ts

BEGIN;

-- SSO configuration per team (SAML IdP settings)
CREATE TABLE IF NOT EXISTS sso_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL DEFAULT 'saml',
    enabled BOOLEAN NOT NULL DEFAULT false,
    idp_entity_id TEXT NOT NULL,
    idp_sso_url TEXT NOT NULL,
    idp_certificate TEXT NOT NULL,
    idp_metadata_url TEXT,
    sp_entity_id TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    force_authn BOOLEAN NOT NULL DEFAULT false,
    allow_unencrypted_assertion BOOLEAN NOT NULL DEFAULT false,
    sign_authn_request BOOLEAN NOT NULL DEFAULT true,
    default_role TEXT NOT NULL DEFAULT 'member',
    auto_provision_users BOOLEAN NOT NULL DEFAULT true,
    auto_add_to_team BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_sso_configurations_team UNIQUE (team_id)
);

CREATE INDEX IF NOT EXISTS idx_sso_configurations_team_id ON sso_configurations(team_id);

-- SSO session tracking (SAML auth flow state)
CREATE TABLE IF NOT EXISTS sso_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sso_config_id UUID NOT NULL REFERENCES sso_configurations(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    relay_state TEXT,
    ip_address INET,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'expired', 'failed')),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sso_sessions_request_id ON sso_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_config_status ON sso_sessions(sso_config_id, status);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_user_id ON sso_sessions(user_id);

-- GDPR Article 30: Records of processing activities
CREATE TABLE IF NOT EXISTS processing_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    purpose TEXT NOT NULL,
    legal_basis TEXT NOT NULL,
    data_categories JSONB NOT NULL DEFAULT '["security_scan_data"]',
    recipient_categories JSONB NOT NULL DEFAULT '["data_subject"]',
    retention_period TEXT DEFAULT '90 days',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_processing_records_user_id ON processing_records(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_records_created_at ON processing_records(created_at);

-- Add SSO columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject_id TEXT;

CREATE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject_id)
    WHERE sso_provider IS NOT NULL;

COMMIT;
