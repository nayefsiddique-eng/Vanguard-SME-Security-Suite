-- Run against a reviewed backup or the verified historical schema before startup.
BEGIN;

-- Existing accounts did not have roles. The owner can restore approved grants
-- individually. Leave this grant as a backfill rule only.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR;
UPDATE users SET role = 'Read Only' WHERE role IS NULL;

-- Older rows have no recoverable scan date. Keep those timestamps unknown.
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP WITHOUT TIME ZONE;

COMMIT;
