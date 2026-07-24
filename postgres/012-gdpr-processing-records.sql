-- Migration 012: GDPR Processing Records (Article 30)
--
-- Tracks all data processing activities for each user.
-- Required for GDPR Article 30 Record of Processing Activities.

BEGIN;

CREATE TABLE IF NOT EXISTS processing_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,    -- data_export, data_erasure, scan, login, etc.
    purpose TEXT NOT NULL,           -- Legal purpose of processing
    legal_basis VARCHAR(100) NOT NULL, -- consent, legitimate_interest, legal_obligation, contract
    data_categories JSONB DEFAULT '["security_scan_data"]'::jsonb,
    recipient_categories JSONB DEFAULT '["data_subject"]'::jsonb,
    retention_period VARCHAR(50) DEFAULT '2 years',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Data residency configuration per user/team
ALTER TABLE users ADD COLUMN IF NOT EXISTS data_region VARCHAR(10) DEFAULT 'us';
ALTER TABLE teams ADD COLUMN IF NOT EXISTS data_region VARCHAR(10) DEFAULT 'us';

CREATE INDEX IF NOT EXISTS idx_processing_records_user_id ON processing_records(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_records_action ON processing_records(action);
CREATE INDEX IF NOT EXISTS idx_processing_records_created ON processing_records(created_at);

COMMIT;
