-- Add refresh_expires_at column to accounts table
ALTER TABLE accounts ADD COLUMN refresh_expires_at DATETIME; 