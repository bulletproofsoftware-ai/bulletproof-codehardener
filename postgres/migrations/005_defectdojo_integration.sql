-- Migration: 005_defectdojo_integration
-- Add DefectDojo integration columns to projects and scans

-- Projects: store DefectDojo product ID for sync
ALTER TABLE projects ADD COLUMN IF NOT EXISTS defectdojo_product_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_projects_dd_product ON projects(defectdojo_product_id) WHERE defectdojo_product_id IS NOT NULL;

-- Scans: store DefectDojo engagement ID for result import
ALTER TABLE scans ADD COLUMN IF NOT EXISTS defectdojo_engagement_id INTEGER;
CREATE INDEX IF NOT EXISTS idx_scans_dd_engagement ON scans(defectdojo_engagement_id) WHERE defectdojo_engagement_id IS NOT NULL;

-- Scans: store n8n execution ID for workflow tracking
ALTER TABLE scans ADD COLUMN IF NOT EXISTS n8n_execution_id VARCHAR(255);
