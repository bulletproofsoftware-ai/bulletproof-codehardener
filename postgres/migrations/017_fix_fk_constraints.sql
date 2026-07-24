-- Migration 017: Fix foreign key constraints
-- 1. registry_credentials.user_id: TEXT → UUID with FK to users(id)
-- 2. findings.dismissed_by: Add ON DELETE SET NULL

-- ============================================================
-- Fix 1: registry_credentials.user_id
-- Change from TEXT (no FK) to UUID with proper FK constraint
-- ============================================================

-- Drop any existing data that can't be cast (safety — should be empty or valid UUIDs)
DELETE FROM registry_credentials WHERE user_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

ALTER TABLE registry_credentials ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

ALTER TABLE registry_credentials ADD CONSTRAINT fk_registry_credentials_user
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- ============================================================
-- Fix 2: findings.dismissed_by
-- Replace the inline FK (no ON DELETE) with ON DELETE SET NULL
-- ============================================================

-- Drop the existing unnamed FK constraint on dismissed_by
-- Postgres auto-names inline FKs as: findings_dismissed_by_fkey
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_dismissed_by_fkey;

ALTER TABLE findings ADD CONSTRAINT findings_dismissed_by_fkey
  FOREIGN KEY (dismissed_by) REFERENCES users(id) ON DELETE SET NULL;
