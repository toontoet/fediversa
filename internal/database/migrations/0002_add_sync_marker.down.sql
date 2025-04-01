-- Remove last checked post ID marker from accounts table
-- Note: SQLite doesn't easily support DROP COLUMN before version 3.35.
-- A common workaround is to recreate the table, but for simplicity during development,
-- and assuming potential data loss is acceptable if downgrading this far,
-- we might omit the perfect rollback. A better approach involves temporary tables.
-- For now, we just leave the column if downgrading (or handle manually).
-- If you need robust downgrades, the process is more complex:
-- 1. BEGIN TRANSACTION;
-- 2. CREATE TEMP TABLE accounts_backup(...); -- without the new column
-- 3. INSERT INTO accounts_backup SELECT id, service, ... FROM accounts;
-- 4. DROP TABLE accounts;
-- 5. CREATE TABLE accounts (...); -- Original schema without the column
-- 6. INSERT INTO accounts SELECT id, service, ... FROM accounts_backup;
-- 7. DROP TABLE accounts_backup;
-- 8. COMMIT;

-- Simple approach (no actual column drop for older SQLite versions):
SELECT 1; -- No-op, prevents error but doesn't drop column on older SQLite 