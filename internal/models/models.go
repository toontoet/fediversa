package models

import (
	"database/sql"
	"time"
)

// Account represents the data stored for a linked social media account.
// Corresponds to the 'accounts' table in the database.
type Account struct {
	ID                int64          `db:"id"`                   // Primary key
	Service           string         `db:"service"`              // 'mastodon' or 'bluesky'
	UserID            string         `db:"user_id"`              // User ID on the service
	Username          string         `db:"username"`             // Username/handle on the service
	AccessToken       sql.NullString `db:"access_token"`         // OAuth access token (nullable)
	RefreshToken      sql.NullString `db:"refresh_token"`        // OAuth refresh token (nullable)
	AppPassword       sql.NullString `db:"app_password"`         // Bluesky app password (nullable)
	ExpiresAt         sql.NullTime   `db:"expires_at"`           // Token expiry time (nullable)
	LastCheckedPostID sql.NullString `db:"last_checked_post_id"` // ID of the last post retrieved from this service (nullable)
	CreatedAt         time.Time      `db:"created_at"`           // Timestamp of creation
	UpdatedAt         time.Time      `db:"updated_at"`           // Timestamp of last update
}

// SyncedPost represents a record of a post that has been synced between services.
// Corresponds to the 'synced_posts' table in the database.
type SyncedPost struct {
	ID            int64     `db:"id"`             // Primary key
	SourceService string    `db:"source_service"` // Service where the post originated ('mastodon' or 'bluesky')
	SourcePostID  string    `db:"source_post_id"` // ID of the original post
	TargetService string    `db:"target_service"` // Service where the post was synced to ('mastodon' or 'bluesky')
	TargetPostID  string    `db:"target_post_id"` // ID of the synced post on the target service
	CreatedAt     time.Time `db:"created_at"`     // Timestamp of when the sync occurred
}

// MediaAttachment represents media attached to a post during the sync process.
// This is an intermediate representation, not stored directly in the DB.
type MediaAttachment struct {
	URL         string // Original URL of the media
	Data        []byte // Raw data of the downloaded media
	ContentType string // Detected content type (e.g., "image/jpeg")
	Description string // Alt text or description
	Filename    string // Derived filename

	// Fields to hold the platform-specific representation after upload
	Blob       interface{} // Stores *lexutil.LexBlob for Bluesky
	Attachment interface{} // Stores *mastodon.Attachment for Mastodon
}
