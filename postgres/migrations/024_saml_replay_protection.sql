-- Migration 024: SAML replay protection
-- Required by: backend/src/services/sso/assertion-replay.ts,
--              backend/src/services/sso/sso-session-cache.ts,
--              backend/src/services/sso/saml.service.ts
--
-- Adds:
--   1. saml_assertion_replay -- single-use assertion IDs
--   2. partial unique index on sso_sessions(sso_config_id, request_id) WHERE status='pending'
--      -- makes InResponseTo single-use enforceable
--
-- DEPLOYMENT NOTE: this change ships with SSO_ENABLED defaulting to "false".
-- Existing deployments that use SAML SSO must set SSO_ENABLED=true, and must be
-- aware of two intentional behaviour changes: an email resolving to a user
-- outside the configuration's team now rejects rather than authenticating, and
-- a local-password account is no longer silently adopted into SSO on first
-- SSO login.

BEGIN;

-- ============================================================
-- 1. saml_assertion_replay -- reject a previously-seen assertion ID
-- ============================================================
CREATE TABLE IF NOT EXISTS saml_assertion_replay (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sso_config_id UUID NOT NULL REFERENCES sso_configurations(id) ON DELETE CASCADE,
    assertion_id  TEXT NOT NULL,
    seen_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_saml_assertion_replay UNIQUE (sso_config_id, assertion_id)
);

-- Retention sweep: DELETE ... WHERE expires_at < NOW()
CREATE INDEX IF NOT EXISTS idx_saml_assertion_replay_expires_at
    ON saml_assertion_replay(expires_at);

COMMENT ON TABLE saml_assertion_replay IS
    'Single-use SAML assertion IDs. A row means the assertion was consumed; a conflicting '
    'INSERT means replay. Rows are deleted once expires_at passes (assertion NotOnOrAfter '
    '+ clock skew, floored at 10 minutes) - they carry no security value beyond that point.';

-- ============================================================
-- 2. sso_sessions: at most one PENDING row per (config, request_id)
-- ============================================================
-- A partial unique index (rather than a plain UNIQUE on request_id) is used deliberately:
--   * it enforces exactly the invariant that matters - a request_id can be pending once;
--   * it needs NO destructive dedup of historical completed/expired/failed rows, so the
--     existing SSO audit trail is preserved intact;
--   * completed/expired rows may legitimately repeat a request_id over time.
-- Only currently-pending duplicates must be resolved first, and those are ephemeral
-- (they expire after 10 minutes anyway). Expire all but the newest of each duplicate set.
-- In practice request_id is '_' || gen_random_uuid(), so duplicates are astronomically
-- unlikely; this statement exists so the migration cannot fail on a surprise. No row is
-- deleted and no audit history is lost.
UPDATE sso_sessions s
SET    status = 'expired', updated_at = NOW()
WHERE  s.status = 'pending'
  AND  EXISTS (
        SELECT 1 FROM sso_sessions n
        WHERE  n.status        = 'pending'
          AND  n.sso_config_id = s.sso_config_id
          AND  n.request_id    = s.request_id
          AND  (n.created_at, n.id) > (s.created_at, s.id)
       );

CREATE UNIQUE INDEX IF NOT EXISTS uq_sso_sessions_pending_request
    ON sso_sessions (sso_config_id, request_id)
    WHERE status = 'pending';

COMMIT;
