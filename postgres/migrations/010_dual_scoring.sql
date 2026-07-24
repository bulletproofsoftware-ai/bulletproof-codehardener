-- Migration 010: Dual scoring (raw vs adjusted) + finding suppressions
-- Raw score = score at scan completion (all findings counted)
-- Adjusted score = score after triage (only open findings counted)

-- Add raw score column to scans
ALTER TABLE scans ADD COLUMN IF NOT EXISTS score_raw INTEGER;

-- Backfill: existing scans get current score as raw (best approximation)
UPDATE scans SET score_raw = score WHERE score_raw IS NULL AND score IS NOT NULL;

-- Finding suppression rules: project-level auto-triage
CREATE TABLE IF NOT EXISTS finding_suppressions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    match_type VARCHAR(50) NOT NULL,
    match_value TEXT NOT NULL,
    target_status VARCHAR(50) NOT NULL DEFAULT 'accepted_risk',
    reason TEXT,
    comment TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suppressions_project ON finding_suppressions(project_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_active ON finding_suppressions(project_id, is_active) WHERE is_active = TRUE;

-- Add updated_at trigger
CREATE TRIGGER update_finding_suppressions_updated_at BEFORE UPDATE ON finding_suppressions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
