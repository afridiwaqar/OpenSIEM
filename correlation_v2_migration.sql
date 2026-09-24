-- =============================================================================
-- OpenSIEM — Correlation Engine v2 Migration
-- Run once: psql -U waqar -d museum -f correlation_v2_migration.sql
-- =============================================================================

BEGIN;

-- Add time window and cooldown to use_cases
ALTER TABLE use_cases
    ADD COLUMN IF NOT EXISTS time_window_seconds  INTEGER DEFAULT 300,
    ADD COLUMN IF NOT EXISTS cooldown_seconds     INTEGER DEFAULT 600,
    ADD COLUMN IF NOT EXISTS threshold_count      INTEGER DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS threshold_window_seconds INTEGER DEFAULT NULL;

-- Set sensible defaults for existing rules
UPDATE use_cases SET
    time_window_seconds = 300,
    cooldown_seconds    = 600
WHERE time_window_seconds IS NULL;

COMMIT;

-- Verify
SELECT
    case_id, case_name, entity_field, severity,
    time_window_seconds, cooldown_seconds,
    threshold_count, threshold_window_seconds
FROM use_cases
ORDER BY case_id;
