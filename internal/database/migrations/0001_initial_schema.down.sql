-- Revert initial schema

DROP TRIGGER IF EXISTS update_accounts_updated_at;
DROP TABLE IF EXISTS synced_posts;
DROP TABLE IF EXISTS accounts;
