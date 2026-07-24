-- Migration 016: Project scan context for DAST/container/API scanning
-- Adds target_url, container_image, openapi_spec_path, auth_config to projects
-- Creates registry_credentials table for private registry auth

-- Project scan context fields (all nullable, backward-compatible)
ALTER TABLE projects ADD COLUMN IF NOT EXISTS target_url TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS container_image TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS openapi_spec_path TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS auth_config JSONB;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS registry_credentials_id UUID;

CREATE INDEX IF NOT EXISTS idx_projects_target_url ON projects (target_url) WHERE target_url IS NOT NULL;

-- Registry credentials table (follows github_connections encryption pattern)
CREATE TABLE IF NOT EXISTS registry_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  registry TEXT NOT NULL,
  username TEXT NOT NULL,
  password_encrypted TEXT NOT NULL,
  password_iv VARCHAR(24) NOT NULL,
  password_tag VARCHAR(24) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registry_credentials_user ON registry_credentials (user_id);

ALTER TABLE projects DROP CONSTRAINT IF EXISTS fk_projects_registry_credentials;
ALTER TABLE projects ADD CONSTRAINT fk_projects_registry_credentials
  FOREIGN KEY (registry_credentials_id) REFERENCES registry_credentials(id) ON DELETE SET NULL;

-- Ensure auth_config password is always stored as encrypted object, never plaintext string
ALTER TABLE projects DROP CONSTRAINT IF EXISTS chk_auth_config_password_encrypted;
ALTER TABLE projects ADD CONSTRAINT chk_auth_config_password_encrypted
  CHECK (auth_config IS NULL OR (auth_config->'password' IS NOT NULL AND jsonb_typeof(auth_config->'password') = 'object'));

COMMENT ON COLUMN projects.auth_config IS 'DAST authentication config. password field is always {encrypted, iv, tag}, never plaintext.';

-- Auto-update trigger for registry_credentials
DROP TRIGGER IF EXISTS update_registry_credentials_updated_at ON registry_credentials;
CREATE TRIGGER update_registry_credentials_updated_at BEFORE UPDATE ON registry_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
