-- Initial database schema for FediVersa

-- accounts table: Stores credentials and basic info for the linked accounts.
-- We assume only one pair of accounts is linked initially.
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL UNIQUE, -- 'mastodon' or 'bluesky'
    user_id TEXT NOT NULL,        -- User ID on the service (e.g., Mastodon account ID, Bluesky DID)
    username TEXT NOT NULL,       -- Username/handle on the service
    access_token TEXT,            -- Access token (e.g., Mastodon OAuth token)
    refresh_token TEXT,           -- Refresh token (if applicable)
    app_password TEXT,            -- App password (e.g., for Bluesky)
    expires_at DATETIME,          -- Token expiry time (if applicable)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- synced_posts table: Tracks which posts have been synced between networks.
CREATE TABLE IF NOT EXISTS synced_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_service TEXT NOT NULL, -- 'mastodon' or 'bluesky'
    source_post_id TEXT NOT NULL, -- ID of the original post on the source service
    target_service TEXT NOT NULL, -- 'mastodon' or 'bluesky'
    target_post_id TEXT NOT NULL, -- ID of the corresponding post on the target service
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_service, source_post_id, target_service) -- Ensure we don't sync the same post multiple times
);

-- Trigger to automatically update 'updated_at' timestamp on accounts table
CREATE TRIGGER IF NOT EXISTS update_accounts_updated_at
AFTER UPDATE ON accounts
FOR EACH ROW
BEGIN
    UPDATE accounts SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;
