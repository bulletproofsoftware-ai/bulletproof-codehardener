-- Migration 015: Quality Terminology Rename
-- Renames risk_level to quality_level, accepted_risk to deferred

-- Rename column on scans table
ALTER TABLE scans RENAME COLUMN risk_level TO quality_level;

-- Update finding status: accepted_risk → deferred
UPDATE findings SET status = 'deferred' WHERE status = 'accepted_risk';
UPDATE findings SET dismissed_reason = 'deferred' WHERE dismissed_reason = 'accepted_risk';

-- Update suppression default target status
ALTER TABLE finding_suppressions ALTER COLUMN target_status SET DEFAULT 'deferred';
UPDATE finding_suppressions SET target_status = 'deferred' WHERE target_status = 'accepted_risk';
