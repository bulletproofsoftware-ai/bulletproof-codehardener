-- Migration 010: Row-Level Security for Multi-Tenant Isolation
--
-- Enforces that users can only access their own data at the database level,
-- providing defense-in-depth beyond application-layer auth checks.
--
-- Implementation approach:
--   1. Create an app role (codehardener_app) that connections use
--   2. Enable RLS on tenant-scoped tables
--   3. Policies check current_setting('app.user_id') against user_id columns
--   4. The backend sets this session variable before each request

BEGIN;

-- Create application role if it doesn't exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'codehardener_app') THEN
    CREATE ROLE codehardener_app LOGIN;
  END IF;
END
$$;

-- Grant necessary permissions to the app role
GRANT USAGE ON SCHEMA public TO codehardener_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO codehardener_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO codehardener_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO codehardener_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO codehardener_app;

-- ============================================================================
-- Helper function to get the current user ID from session variable
-- ============================================================================

CREATE OR REPLACE FUNCTION current_app_user_id() RETURNS UUID AS $$
BEGIN
  RETURN current_setting('app.user_id', true)::UUID;
EXCEPTION
  WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- Enable RLS on tenant-scoped tables
-- ============================================================================

-- Projects: user_id column
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;

CREATE POLICY projects_tenant_isolation ON projects
  USING (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());

-- Scans: accessed via project_id → projects.user_id
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;

CREATE POLICY scans_tenant_isolation ON scans
  USING (project_id IN (SELECT id FROM projects WHERE user_id = current_app_user_id()))
  WITH CHECK (project_id IN (SELECT id FROM projects WHERE user_id = current_app_user_id()));

-- Findings: has project_id column directly
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;

CREATE POLICY findings_tenant_isolation ON findings
  USING (project_id IN (SELECT id FROM projects WHERE user_id = current_app_user_id()))
  WITH CHECK (project_id IN (SELECT id FROM projects WHERE user_id = current_app_user_id()));

-- Attestations: via scan_id → scans → projects
ALTER TABLE attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestations FORCE ROW LEVEL SECURITY;

CREATE POLICY attestations_tenant_isolation ON attestations
  USING (scan_id IN (
    SELECT s.id FROM scans s
    JOIN projects p ON p.id = s.project_id
    WHERE p.user_id = current_app_user_id()
  ));

-- API Keys: user_id column
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON api_keys
  USING (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());

-- Policies (OPA/custom): user_id column
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;

CREATE POLICY policies_tenant_isolation ON policies
  USING (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());

-- ============================================================================
-- Bypass policy for the superuser/owner role (used by migrations, admin tasks)
-- The default postgres role bypasses RLS automatically.
-- ============================================================================

-- Create indexes to support RLS subquery performance
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project_id ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_user_id_rls ON policies(user_id);

COMMIT;
