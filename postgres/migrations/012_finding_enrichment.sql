-- Migration 012: Finding Enrichment Pipeline
-- Adds columns for exploitability scoring, reachability filtering,
-- dataflow analysis, and LLM verification results.

-- Add enrichment columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploitability VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reachable BOOLEAN;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dataflow_match VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS llm_verified BOOLEAN;

-- Indexes for efficient filtering on new columns
CREATE INDEX IF NOT EXISTS idx_findings_exploitability ON findings(exploitability);
CREATE INDEX IF NOT EXISTS idx_findings_reachable ON findings(reachable);

-- Add code_analysis_summary JSONB to scans for caching analysis results
ALTER TABLE scans ADD COLUMN IF NOT EXISTS code_analysis_summary JSONB;
