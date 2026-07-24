-- Migration 011: SSO/SAML Authentication Support
--
-- Stores SSO configuration per team. Only available to Team/Enterprise tiers.
-- Supports SAML 2.0 with IdP metadata, certificates, and assertion mapping.

BEGIN;

-- SSO Configurations (one per team)
CREATE TABLE IF NOT EXISTS sso_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    provider_type VARCHAR(20) NOT NULL DEFAULT 'saml', -- saml, oidc (future)
    enabled BOOLEAN DEFAULT FALSE,

    -- SAML-specific fields
    idp_entity_id TEXT NOT NULL,
    idp_sso_url TEXT NOT NULL,
    idp_certificate TEXT NOT NULL, -- PEM-encoded X.509 certificate
    idp_metadata_url TEXT,         -- Optional: auto-fetch metadata

    -- SP (our side) configuration
    sp_entity_id TEXT NOT NULL,    -- e.g. https://api.codehardener.com/saml/metadata
    sp_acs_url TEXT NOT NULL,      -- Assertion Consumer Service URL

    -- Assertion mapping
    attribute_mapping JSONB DEFAULT '{
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "groups": "http://schemas.xmlsoap.org/claims/Group"
    }'::jsonb,

    -- Settings
    force_authn BOOLEAN DEFAULT FALSE,
    allow_unencrypted_assertion BOOLEAN DEFAULT FALSE,
    sign_authn_request BOOLEAN DEFAULT TRUE,
    default_role VARCHAR(50) DEFAULT 'member',

    -- Auto-provisioning
    auto_provision_users BOOLEAN DEFAULT TRUE,
    auto_add_to_team BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(team_id)
);

-- SSO login sessions (tracks in-flight SAML auth flows)
CREATE TABLE IF NOT EXISTS sso_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sso_config_id UUID NOT NULL REFERENCES sso_configurations(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,           -- SAML AuthnRequest ID
    relay_state TEXT,                   -- Where to redirect after auth
    status VARCHAR(20) DEFAULT 'pending', -- pending, completed, expired, failed
    user_id UUID REFERENCES users(id),  -- Set after successful auth
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Track SSO-linked accounts
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject_id TEXT;

CREATE INDEX IF NOT EXISTS idx_sso_configurations_team_id ON sso_configurations(team_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_request_id ON sso_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_status ON sso_sessions(status);
CREATE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject_id) WHERE sso_provider IS NOT NULL;

COMMIT;
