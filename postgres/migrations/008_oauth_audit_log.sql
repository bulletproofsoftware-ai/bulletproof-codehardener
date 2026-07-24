-- OAuth Audit Log Migration (security-m005)
-- SEC-026: OAuth token operations MUST be logged
-- SEC-026-A: OAuth audit logs MUST be retained for 90 days minimum
-- SEC-026-B: OAuth audit logs MUST be queryable by user_id and time range

CREATE TABLE IF NOT EXISTS oauth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45) NOT NULL,  -- Supports IPv4 and IPv6
    user_agent TEXT,
    result VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failure')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for SEC-026-B: queryable by user_id and time range
CREATE INDEX IF NOT EXISTS idx_oauth_audit_user_id ON oauth_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_audit_timestamp ON oauth_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_oauth_audit_event_type ON oauth_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_oauth_audit_result ON oauth_audit_log(result);

-- Composite index for common query pattern (user + time range)
CREATE INDEX IF NOT EXISTS idx_oauth_audit_user_timestamp
    ON oauth_audit_log(user_id, timestamp DESC);

-- Comments
COMMENT ON TABLE oauth_audit_log IS 'Audit log for OAuth token operations (SEC-026). Minimum 90-day retention.';
COMMENT ON COLUMN oauth_audit_log.event_type IS 'Type: token_created, token_refreshed, token_revoked, token_validation_failed, scope_changed, connection_expired';
COMMENT ON COLUMN oauth_audit_log.ip_address IS 'Client IP address (supports IPv4 and IPv6)';
COMMENT ON COLUMN oauth_audit_log.details IS 'JSON details: scopes, reason, connectionId, githubUsername, etc.';
