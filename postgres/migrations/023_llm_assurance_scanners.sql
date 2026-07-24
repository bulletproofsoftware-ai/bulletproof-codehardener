-- Migration 023: LLM Assurance Scanners (defending-code-reference-harness integration)
-- Required by: backend/src/services/scanners/llm-threatmodel.ts, llm-vuln-scan.ts,
--              llm-triage.ts, llm-patch.ts
--
-- Adds:
--   1. threat_models       — persistent per-project THREAT_MODEL.md artifact (one per project)
--   2. candidate_patches   — LLM-proposed fixes for verified findings (never auto-applied)
--   3. projects.llm_analysis_enabled — privacy opt-in gate (spec §11 R3)
--
-- PK/FK columns are UUID to match projects.id / findings.id (spec §12). Free-text
-- columns are TEXT per project convention. Fully idempotent (IF NOT EXISTS / DO NOTHING).

BEGIN;

-- ============================================================
-- 1. threat_models — persistent per-project threat model
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,                       -- THREAT_MODEL.md markdown (harness schema.md contract)
    threats_json TEXT NOT NULL DEFAULT '[]',     -- parsed section 4 threats table (JSON array)
    source_inventory_hash TEXT NOT NULL,         -- staleness detection
    model_used TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 2. candidate_patches — LLM-proposed fixes (metadata only, never auto-applied)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidate_patches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    -- A5: scan_id is a real FK so patches cascade-delete with their scan.
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    patch_diff TEXT NOT NULL,
    rationale TEXT NOT NULL,
    validation_notes TEXT NOT NULL,              -- build / exploit-path-closed / tests / bypass checklist (LLM self-assessment)
    model_used TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'accepted', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- F4: retry idempotency — BullMQ attempts:3 re-runs the patch stage, which
    -- re-INSERTs the same (finding_id, scan_id). The unique constraint backs the
    -- ON CONFLICT (finding_id, scan_id) DO NOTHING in insertPatch (llm-patch.ts).
    CONSTRAINT uq_candidate_patches_finding_scan UNIQUE (finding_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_candidate_patches_finding ON candidate_patches(finding_id);
CREATE INDEX IF NOT EXISTS idx_candidate_patches_scan ON candidate_patches(scan_id);

-- ============================================================
-- 3. projects.llm_analysis_enabled — privacy opt-in (spec §11 R3)
-- ============================================================
ALTER TABLE projects ADD COLUMN IF NOT EXISTS llm_analysis_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON TABLE threat_models IS 'Persistent per-project LLM-generated threat model (defending-code-reference-harness bootstrap)';
COMMENT ON TABLE candidate_patches IS 'LLM-proposed candidate fixes for verified findings; status is metadata only, never auto-applied';
COMMENT ON COLUMN projects.llm_analysis_enabled IS 'Privacy opt-in: when TRUE, project source may be transmitted to Anthropic for LLM assurance scanning';

INSERT INTO schema_migrations (version, name) VALUES
    ('023', 'llm_assurance_scanners')
ON CONFLICT (version) DO NOTHING;

COMMIT;
