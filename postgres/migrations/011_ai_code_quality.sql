-- Migration 011: AI Code Quality scanner support
-- Adds columns for mutation testing scores, license risk counts,
-- and hallucinated package counts from the new AI code quality scanners.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS mutation_score NUMERIC(5,2);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS license_risk_count INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS hallucinated_package_count INTEGER DEFAULT 0;
