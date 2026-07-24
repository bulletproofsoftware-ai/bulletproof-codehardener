-- Migration: Test Generator Tables
-- Adds tables for code analysis, BRD analysis, and generated test cases

-- =============================================================================
-- Code Analysis Results Table
-- Stores results from CA-001 to CA-010 code analysis modules
-- =============================================================================
CREATE TABLE IF NOT EXISTS code_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repository_url TEXT,
    analysis_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- CA-001: Language detection
    detected_languages JSONB NOT NULL DEFAULT '[]',

    -- CA-002: Framework detection
    detected_frameworks JSONB NOT NULL DEFAULT '[]',

    -- CA-003: Endpoint extraction
    extracted_endpoints JSONB NOT NULL DEFAULT '[]',

    -- CA-004: Authentication patterns
    auth_patterns JSONB NOT NULL DEFAULT '[]',

    -- CA-005: Data flow tracing
    data_flows JSONB NOT NULL DEFAULT '[]',

    -- CA-006: Sensitive data identification
    sensitive_data_points JSONB NOT NULL DEFAULT '[]',

    -- CA-007: Dependency parsing
    dependencies JSONB NOT NULL DEFAULT '[]',

    -- CA-008: Infrastructure file detection
    infrastructure_files JSONB NOT NULL DEFAULT '[]',

    -- CA-009: Code summary
    code_summary JSONB,

    -- Processing status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    processing_time_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- BRD Analysis Results Table
-- Stores parsed BRD documents (BP-001 to BP-003)
-- =============================================================================
CREATE TABLE IF NOT EXISTS brd_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    document_name TEXT NOT NULL,
    document_type VARCHAR(20) NOT NULL,
    analysis_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Parsed requirements
    requirements JSONB NOT NULL DEFAULT '[]',
    security_requirements JSONB NOT NULL DEFAULT '[]',
    functional_requirements JSONB NOT NULL DEFAULT '[]',

    -- Processing status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Generated Test Cases Table
-- Stores test cases from TG-001 to TG-003 generators
-- =============================================================================
CREATE TABLE IF NOT EXISTS generated_test_cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    code_analysis_id UUID REFERENCES code_analysis_results(id) ON DELETE SET NULL,
    brd_analysis_id UUID REFERENCES brd_analysis_results(id) ON DELETE SET NULL,

    -- Test case details
    title TEXT NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,

    -- OWASP Top 10 mapping (TG-001)
    owasp_category VARCHAR(20),

    -- CWE Top 25 mapping (TG-002)
    cwe_id INTEGER,

    -- BRD requirement alignment (TG-003)
    aligned_requirement_id TEXT,
    alignment_confidence DECIMAL(3,2),

    -- Test execution details
    test_prompt TEXT NOT NULL,
    target_file TEXT,
    target_endpoint TEXT,
    target_function TEXT,

    -- Recommended scanners
    recommended_scanners JSONB NOT NULL DEFAULT '[]',

    -- Priority and severity
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    expected_severity VARCHAR(20),

    -- Execution tracking
    executed BOOLEAN DEFAULT FALSE,
    execution_date TIMESTAMP WITH TIME ZONE,
    scan_result_id UUID,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Code analysis indexes
CREATE INDEX IF NOT EXISTS idx_code_analysis_project ON code_analysis_results(project_id);
CREATE INDEX IF NOT EXISTS idx_code_analysis_status ON code_analysis_results(status);
CREATE INDEX IF NOT EXISTS idx_code_analysis_created_at ON code_analysis_results(created_at DESC);

-- BRD analysis indexes
CREATE INDEX IF NOT EXISTS idx_brd_analysis_project ON brd_analysis_results(project_id);
CREATE INDEX IF NOT EXISTS idx_brd_analysis_status ON brd_analysis_results(status);
CREATE INDEX IF NOT EXISTS idx_brd_analysis_created_at ON brd_analysis_results(created_at DESC);

-- Generated test cases indexes
CREATE INDEX IF NOT EXISTS idx_test_cases_project ON generated_test_cases(project_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_category ON generated_test_cases(category);
CREATE INDEX IF NOT EXISTS idx_test_cases_owasp ON generated_test_cases(owasp_category);
CREATE INDEX IF NOT EXISTS idx_test_cases_cwe ON generated_test_cases(cwe_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_priority ON generated_test_cases(priority);
CREATE INDEX IF NOT EXISTS idx_test_cases_executed ON generated_test_cases(executed);
CREATE INDEX IF NOT EXISTS idx_test_cases_code_analysis ON generated_test_cases(code_analysis_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_brd_analysis ON generated_test_cases(brd_analysis_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_requirement ON generated_test_cases(aligned_requirement_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_created_at ON generated_test_cases(created_at DESC);

-- =============================================================================
-- Updated_at Triggers
-- =============================================================================

CREATE TRIGGER update_code_analysis_results_updated_at
    BEFORE UPDATE ON code_analysis_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_brd_analysis_results_updated_at
    BEFORE UPDATE ON brd_analysis_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_generated_test_cases_updated_at
    BEFORE UPDATE ON generated_test_cases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Comments for Documentation
-- =============================================================================

COMMENT ON TABLE code_analysis_results IS 'Stores code repository analysis results from CA-001 to CA-010 modules';
COMMENT ON TABLE brd_analysis_results IS 'Stores parsed BRD document results from BP-001 to BP-003 modules';
COMMENT ON TABLE generated_test_cases IS 'Stores generated test cases from TG-001 to TG-003 modules';

COMMENT ON COLUMN code_analysis_results.detected_languages IS 'CA-001: Language detection results with percentages';
COMMENT ON COLUMN code_analysis_results.detected_frameworks IS 'CA-002: Framework detection with confidence scores';
COMMENT ON COLUMN code_analysis_results.extracted_endpoints IS 'CA-003: API endpoints with methods, paths, parameters';
COMMENT ON COLUMN code_analysis_results.auth_patterns IS 'CA-004: Authentication pattern detection (JWT, OAuth, etc.)';
COMMENT ON COLUMN code_analysis_results.data_flows IS 'CA-005: Data flow tracing from sources to sinks';
COMMENT ON COLUMN code_analysis_results.sensitive_data_points IS 'CA-006: Sensitive data identification (PII, credentials)';
COMMENT ON COLUMN code_analysis_results.dependencies IS 'CA-007: Parsed dependencies from manifest files';
COMMENT ON COLUMN code_analysis_results.infrastructure_files IS 'CA-008: Infrastructure file detection (Docker, K8s, Terraform)';
COMMENT ON COLUMN code_analysis_results.code_summary IS 'CA-009: Generated code summary with security concerns';

COMMENT ON COLUMN generated_test_cases.owasp_category IS 'TG-001: OWASP Top 10 2021 category mapping';
COMMENT ON COLUMN generated_test_cases.cwe_id IS 'TG-002: CWE Top 25 2023 ID mapping';
COMMENT ON COLUMN generated_test_cases.aligned_requirement_id IS 'TG-003: BRD requirement ID alignment';
COMMENT ON COLUMN generated_test_cases.alignment_confidence IS 'TG-003: Confidence score for BRD alignment (0.00-1.00)';
