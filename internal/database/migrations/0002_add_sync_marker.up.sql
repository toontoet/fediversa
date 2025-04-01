-- Add last checked post ID marker to accounts table

ALTER TABLE accounts ADD COLUMN last_checked_post_id TEXT; 