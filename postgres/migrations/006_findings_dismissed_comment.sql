-- Migration: 006_findings_dismissed_comment
-- Add dismissed_comment column (dismissed_at and dismissed_reason already exist in init.sql)

-- Only add if not exists (dismissed_comment may not be in original schema)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dismissed_comment TEXT;

-- Ensure dismissed_at exists (should already from init.sql)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dismissed_at TIMESTAMP WITH TIME ZONE;

-- Add index for dismissed findings queries
CREATE INDEX IF NOT EXISTS idx_findings_dismissed ON findings(status, dismissed_at) WHERE status = 'dismissed';
