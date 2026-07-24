-- Migration 018: Database Hardening
-- 1. Composite indexes for common query patterns
-- 2. CHECK constraints on enum-like columns
-- 3. Missing updated_at triggers for 6 tables
-- 4. Migration tracking table (schema_migrations)

-- ============================================================================
-- 1. Composite indexes for performance
-- ============================================================================

-- Findings: scan + status (used in scan results page, status filtering)
CREATE INDEX IF NOT EXISTS idx_findings_scan_status ON findings(scan_id, status);

-- Findings: project + status + severity (used in project findings dashboard)
CREATE INDEX IF NOT EXISTS idx_findings_project_status_severity ON findings(project_id, status, severity);

-- Scans: project + status + created_at (used in project scan history, sorted)
CREATE INDEX IF NOT EXISTS idx_scans_project_status_created ON scans(project_id, status, created_at DESC);

-- Findings: tool_name partial index (used in scanner coverage queries)
CREATE INDEX IF NOT EXISTS idx_findings_tool_name ON findings(tool_name) WHERE tool_name IS NOT NULL;

-- ============================================================================
-- 2. CHECK constraints on enum-like columns
-- ============================================================================

-- findings.status: open | fixed | ignored | false_positive | deferred
ALTER TABLE findings ADD CONSTRAINT chk_findings_status
    CHECK (status IN ('open', 'fixed', 'ignored', 'false_positive', 'deferred'));

-- findings.severity: critical | high | medium | low | info
ALTER TABLE findings ADD CONSTRAINT chk_findings_severity
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));

-- findings.exploitability: NULL or confirmed | likely | theoretical | unlikely
ALTER TABLE findings ADD CONSTRAINT chk_findings_exploitability
    CHECK (exploitability IS NULL OR exploitability IN ('confirmed', 'likely', 'theoretical', 'unlikely'));

-- findings.dataflow_match: NULL or direct | indirect | sanitized | none
ALTER TABLE findings ADD CONSTRAINT chk_findings_dataflow
    CHECK (dataflow_match IS NULL OR dataflow_match IN ('direct', 'indirect', 'sanitized', 'none'));

-- scans.status: pending | running | completed | failed | cancelled
ALTER TABLE scans ADD CONSTRAINT chk_scans_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'));

-- ============================================================================
-- 3. Missing updated_at triggers
-- These 6 tables have updated_at columns but no auto-update trigger
-- ============================================================================

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
-- 4. Migration tracking table
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert all historical migrations (idempotent)
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
    ('018', 'database_hardening')
ON CONFLICT (version) DO NOTHING;
