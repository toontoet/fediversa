package main

import (
	"context"
	"fediversa/internal/api"
	"fediversa/internal/config"
	"fediversa/internal/database"
	"fediversa/internal/logging"
	"fediversa/internal/sync"
	"fediversa/internal/transform"
	"fediversa/internal/web"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logging.Info("Starting FediVersa...")

	// Load configuration
	cfg := config.LoadConfig()
	logging.Info("Configuration loaded. BaseURL: %s", cfg.BaseURL)
	logging.Info("Effective Config: %+v", redactConfig(cfg))

	// Initialize database connection
	db, err := database.NewDB(cfg.DatabasePath)
	if err != nil {
		logging.Fatal("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logging.Error("Error closing database: %v", err)
		}
	}()

	logging.Info("Database initialized and migrations checked/applied.")

	// Initialize API clients
	mastodonClient := api.NewMastodonClient(cfg)
	blueskyClient, err := api.NewBlueskyClient(cfg)
	if err != nil {
		logging.Error("Failed to initialize Bluesky client (continuing): %v", err)
	}

	// Restore Bluesky session if account exists
	bskyAccount, err := db.GetAccountByService("bluesky")
	if err != nil {
		logging.Error("Failed to check for existing Bluesky account: %v", err)
	} else if bskyAccount != nil {
		err = blueskyClient.SetSession(bskyAccount)
		if err != nil {
			logging.Error("Failed to restore Bluesky session: %v", err)
			// Consider attempting refresh token logic here if needed in the future
		} else {
			logging.Info("Restored existing Bluesky session for %s", bskyAccount.Username)
		}
	}

	// TODO: Restore Mastodon session/client if account exists
	// mastoAccount, err := db.GetAccountByService("mastodon")
	// if err == nil && mastoAccount != nil && mastoAccount.AccessToken.Valid {
	//    authenticatedMastoClient := mastodonClient.GetAuthenticatedClient(mastoAccount.AccessToken.String)
	//    // Store/use authenticatedMastoClient
	//    logging.Info("Restored existing Mastodon session for %s", mastoAccount.Username)
	// }

	// Initialize Transformer
	transformer := transform.NewTransformer(cfg)
	logging.Info("Transformer initialized.")

	// Initialize and start the web server
	webServer := web.NewServer(cfg, db, mastodonClient, blueskyClient /*, transformer */)
	go webServer.Start() // Start in a goroutine so it doesn't block

	// Initialize and start the syncer
	syncer := sync.NewSyncer(db, mastodonClient, blueskyClient, transformer, cfg) // Pass transformer
	// Start syncer in a goroutine or manage its lifecycle appropriately
	// Assuming Syncer has a Run method like before
	ctxApp, stopApp := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopApp()

	go syncer.Run(ctxApp)

	logging.Info("Syncer starting with interval: %s", cfg.SyncInterval.String())

	// Wait for shutdown signal
	logging.Info("Application started. Web UI available at %s. Press Ctrl+C to exit.", cfg.BaseURL)
	<-ctxApp.Done() // Wait for context cancellation from signal

	logging.Info("Shutting down FediVersa...")

	// Gracefully stop the web server
	// Use a derived context for shutdown with timeout
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := webServer.Stop(ctxShutdown); err != nil {
		logging.Error("Error stopping web server: %v", err)
	}

	// Syncer stops automatically when ctxApp is cancelled
	logging.Info("Syncer stopping...")

	// Database connection is closed by defer
	logging.Info("FediVersa stopped.")
}

// redactConfig returns a copy of the config with sensitive fields redacted.
// This is useful for logging the config without exposing secrets.
func redactConfig(cfg *config.Config) *config.Config {
	redacted := *cfg // Create a shallow copy
	if redacted.MastodonClientSecret != "" {
		redacted.MastodonClientSecret = "[REDACTED]"
	}
	if redacted.BlueskyPassword != "" {
		redacted.BlueskyPassword = "[REDACTED]"
	}
	if redacted.WebAuthPassword != "" {
		redacted.WebAuthPassword = "[REDACTED]"
	}
	if redacted.SessionSecret != "" {
		redacted.SessionSecret = "[REDACTED]"
	}
	// Add other sensitive fields here if needed
	return &redacted
}
