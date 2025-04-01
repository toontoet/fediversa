package database

import (
	"database/sql"
	"embed"
	"fmt"
	"net/url"

	"fediversa/internal/logging"
	"fediversa/internal/models"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB represents the database connection.
type DB struct {
	*sql.DB
}

// NewDB opens a connection to the SQLite database specified by the path
// and runs any pending migrations.
func NewDB(dataSourceName string) (*DB, error) {
	logging.Info("Opening database connection to: %s", dataSourceName)
	// Ensure the path is treated correctly, especially on different OSes.
	// We append _foreign_keys=1 to enable foreign key constraints, which is generally a good idea.
	// We also append _journal_mode=WAL for better concurrency.
	u, err := url.Parse(dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("invalid database path: %w", err)
	}
	q := u.Query()
	q.Set("_foreign_keys", "1")
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()

	dbConn, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Check the connection.
	if err = dbConn.Ping(); err != nil {
		dbConn.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logging.Info("Database connection successful.")

	db := &DB{dbConn}

	// Apply migrations
	if err := db.applyMigrations(dataSourceName); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}

	return db, nil
}

// applyMigrations checks the current database schema version and applies
// any pending migrations from the embedded migrations filesystem.
func (db *DB) applyMigrations(dbPath string) error {
	logging.Info("Checking database migrations...")

	// Use iofs source driver for embedded filesystem
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	// Use sqlite3 driver
	// We need a temporary separate connection for migrate as it handles the connection itself.
	// Important: The path here should NOT include the query parameters we added for the main connection.
	// We use the original dbPath for the migration tool.
	driver, err := sqlite3.WithInstance(db.DB, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "sqlite3", driver)
	if err != nil {
		return fmt.Errorf("failed to initialize migrate instance: %w", err)
	}

	err = m.Up() // Apply all up migrations
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	if err == migrate.ErrNoChange {
		logging.Info("Database schema is up to date.")
	} else {
		logging.Info("Database migrations applied successfully.")
	}

	// Close the source connection handle
	srcErr := src.Close()
	// // Close the database connection handle used by migrate - THIS CLOSES THE MAIN CONNECTION!
	// dbErr := driver.Close()

	if srcErr != nil {
		return fmt.Errorf("failed to close migration source: %w", srcErr)
	}
	// if dbErr != nil {
	// 	return fmt.Errorf("failed to close migration driver connection: %w", dbErr)
	// }

	return nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	logging.Info("Closing database connection.")
	return db.DB.Close()
}

// ---- Account Operations ----

// SaveAccount inserts or updates an account in the database based on the service.
// It uses UPSERT logic (ON CONFLICT DO UPDATE).
func (db *DB) SaveAccount(acc *models.Account) error {
	query := `
		INSERT INTO accounts (service, user_id, username, access_token, refresh_token, app_password, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(service) DO UPDATE SET
			user_id = excluded.user_id,
			username = excluded.username,
			access_token = excluded.access_token,
			refresh_token = excluded.refresh_token,
			app_password = excluded.app_password,
			expires_at = excluded.expires_at,
			updated_at = CURRENT_TIMESTAMP;
	`
	_, err := db.Exec(query,
		acc.Service,
		acc.UserID,
		acc.Username,
		acc.AccessToken,
		acc.RefreshToken,
		acc.AppPassword,
		acc.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save account for service %s: %w", acc.Service, err)
	}
	logging.Info("Saved account details for service: %s", acc.Service)
	return nil
}

// GetAccountByService retrieves account details for a specific service.
func (db *DB) GetAccountByService(service string) (*models.Account, error) {
	query := `
		SELECT id, service, user_id, username, access_token, refresh_token, app_password, expires_at,
		       last_checked_post_id, created_at, updated_at
		FROM accounts
		WHERE service = ?;
	`
	row := db.QueryRow(query, service)

	var acc models.Account
	err := row.Scan(
		&acc.ID,
		&acc.Service,
		&acc.UserID,
		&acc.Username,
		&acc.AccessToken,
		&acc.RefreshToken,
		&acc.AppPassword,
		&acc.ExpiresAt,
		&acc.LastCheckedPostID,
		&acc.CreatedAt,
		&acc.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No account found
		}
		return nil, fmt.Errorf("failed to get account for service %s: %w", service, err)
	}
	return &acc, nil
}

// GetLastCheckedPostID retrieves the last checked post ID for a specific service.
func (db *DB) GetLastCheckedPostID(service string) (sql.NullString, error) {
	query := `SELECT last_checked_post_id FROM accounts WHERE service = ?;`
	var lastCheckedID sql.NullString
	err := db.QueryRow(query, service).Scan(&lastCheckedID)
	if err != nil {
		if err == sql.ErrNoRows {
			// No account exists, so return an empty NullString
			return sql.NullString{}, nil
		}
		return sql.NullString{}, fmt.Errorf("failed to get last checked post ID for service %s: %w", service, err)
	}
	return lastCheckedID, nil
}

// UpdateLastCheckedPostID updates the last checked post ID for a specific service.
func (db *DB) UpdateLastCheckedPostID(service string, postID string) error {
	query := `UPDATE accounts SET last_checked_post_id = ?, updated_at = CURRENT_TIMESTAMP WHERE service = ?;`
	result, err := db.Exec(query, postID, service)
	if err != nil {
		return fmt.Errorf("failed to update last checked post ID for service %s: %w", service, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// Error checking rows affected, but update might have succeeded
		logging.Warn("Could not check rows affected after updating last checked post ID for %s: %v", service, err)
	} else if rowsAffected == 0 {
		// This shouldn't happen if the account exists, but good to log
		logging.Warn("UpdateLastCheckedPostID: No account found for service %s, no rows updated.", service)
	}
	return nil
}

// ---- Synced Post Operations ----

// SaveSyncedPost records that a post has been synced.
func (db *DB) SaveSyncedPost(sp *models.SyncedPost) error {
	query := `
		INSERT INTO synced_posts (source_service, source_post_id, target_service, target_post_id, created_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);
	`
	_, err := db.Exec(query, sp.SourceService, sp.SourcePostID, sp.TargetService, sp.TargetPostID)
	if err != nil {
		// Consider if UNIQUE constraint violation should be handled differently (e.g., log as info)
		return fmt.Errorf("failed to save synced post record (source: %s/%s, target: %s/%s): %w",
			sp.SourceService, sp.SourcePostID, sp.TargetService, sp.TargetPostID, err)
	}
	return nil
}

// IsPostSynced checks if a post from a source service has already been synced to a target service.
func (db *DB) IsPostSynced(sourceService, sourcePostID, targetService string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM synced_posts
			WHERE source_service = ? AND source_post_id = ? AND target_service = ?
		);
	`
	var exists bool
	err := db.QueryRow(query, sourceService, sourcePostID, targetService).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if post is synced (source: %s/%s, target: %s): %w",
			sourceService, sourcePostID, targetService, err)
	}
	return exists, nil
}

// CheckIfPostIsFromSync checks if a given post ID on a specific service exists as a TARGET post in the sync table.
// This is used to prevent syncing posts back to their original source (echo prevention).
func (db *DB) CheckIfPostIsFromSync(targetService string, targetPostID string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM synced_posts
			WHERE target_service = ? AND target_post_id = ?
		);
	`
	var exists bool
	err := db.QueryRow(query, targetService, targetPostID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if post %s/%s is from sync: %w",
			targetService, targetPostID, err)
	}
	return exists, nil
}

// GetTargetPostID finds the corresponding target post ID for a given source post ID that was previously synced.
// Returns the targetPostID, a boolean indicating if it was found, and an error.
func (db *DB) GetTargetPostID(sourceService, sourcePostID, targetService string) (string, bool, error) {
	query := `
		SELECT target_post_id
		FROM synced_posts
		WHERE source_service = ? AND source_post_id = ? AND target_service = ?
		LIMIT 1;
	`
	var targetPostID string
	err := db.QueryRow(query, sourceService, sourcePostID, targetService).Scan(&targetPostID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil // Not found, no error
		}
		// Other potential database error
		return "", false, fmt.Errorf("failed to query target post ID for %s/%s -> %s: %w",
			sourceService, sourcePostID, targetService, err)
	}

	// Found the record
	return targetPostID, true, nil
}

// ---- Stats Operations ----

// GetTotalSyncedPosts returns the total number of records in the synced_posts table.
func (db *DB) GetTotalSyncedPosts() (int, error) {
	query := `SELECT COUNT(*) FROM synced_posts;`
	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get total synced posts count: %w", err)
	}
	return count, nil
}

// GetLastSyncTime returns the timestamp of the most recently synced post FROM a specific service.
// Returns sql.NullTime which can be checked for validity.
func (db *DB) GetLastSyncTime(sourceService string) (sql.NullTime, error) {
	query := `SELECT MAX(created_at) FROM synced_posts WHERE source_service = ?;`
	var lastSyncTime sql.NullTime
	err := db.QueryRow(query, sourceService).Scan(&lastSyncTime)
	if err != nil {
		// If no rows found, Scan will return sql.ErrNoRows, but lastSyncTime will remain null/invalid,
		// which is the desired behavior (no syncs yet for this service).
		if err != sql.ErrNoRows {
			return lastSyncTime, fmt.Errorf("failed to get last sync time for service %s: %w", sourceService, err)
		}
	}
	return lastSyncTime, nil
}
