-- Migration 013: Add updated_at to findings table
-- Enables tracking when findings are triaged, dismissed, or enriched

ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Add trigger to auto-update on row modification
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
