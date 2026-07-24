-- Migration: Webhook Dispatcher Extensions
-- Adds columns needed for webhook dispatcher with retry support

-- Add missing columns to webhooks table
ALTER TABLE webhooks
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS headers JSONB DEFAULT '{}';

-- Create index for project-based webhook lookups
CREATE INDEX IF NOT EXISTS idx_webhooks_project_id ON webhooks(project_id);

-- Add missing columns to webhook_deliveries table for retry support
ALTER TABLE webhook_deliveries
  ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 1,
  ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Rename event_type to event for consistency (if needed)
-- Note: Using DO block to handle case where column might already be renamed
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'webhook_deliveries' AND column_name = 'event_type'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'webhook_deliveries' AND column_name = 'event'
  ) THEN
    ALTER TABLE webhook_deliveries RENAME COLUMN event_type TO event;
  END IF;
END $$;

-- Create indexes for delivery queries
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_success ON webhook_deliveries(success);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE next_retry_at IS NOT NULL AND success = FALSE;

-- Update existing deliveries to have success = true and correct created_at
UPDATE webhook_deliveries
SET success = (response_status >= 200 AND response_status < 300),
    created_at = COALESCE(delivered_at, NOW())
WHERE success IS NULL;
