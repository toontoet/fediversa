package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds the application configuration.
type Config struct {
	DatabasePath         string
	SyncInterval         time.Duration
	ListenAddr           string // Address for the web server (e.g., ":8080")
	MastodonServer       string // e.g., "https://mastodon.social"
	MastodonClientID     string
	MastodonClientSecret string
	BlueskyIdentifier    string // Bluesky handle or email
	BlueskyPassword      string // Bluesky app password
	// BaseURL is the public URL where the app is hosted, needed for OAuth callbacks
	BaseURL string
	// SyncBoostsReposts determines if boosts (Mastodon) or reposts (Bluesky) should be synced.
	SyncBoostsReposts bool
	// SuppressNoNewPostsLogs controls logging for sync cycles with no new posts.
	SuppressNoNewPostsLogs bool
	// SyncReplies determines if replies should be synced.
	SyncReplies bool
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() *Config {
	// Load .env file if it exists (useful for development)
	_ = godotenv.Load() // Ignore error if .env file doesn't exist

	intervalMinutesStr := getEnv("SYNC_INTERVAL_MINUTES", "5")
	intervalMinutes, err := strconv.Atoi(intervalMinutesStr)
	if err != nil {
		log.Printf("Invalid SYNC_INTERVAL_MINUTES '%s', using default 5 minutes: %v", intervalMinutesStr, err)
		intervalMinutes = 5
	}

	// Read SyncBoostsReposts env var (default to true)
	syncBoostsStr := getEnv("SYNC_BOOSTS_REPOSTS", "true")
	syncBoosts, err := strconv.ParseBool(syncBoostsStr)
	if err != nil {
		log.Printf("Invalid SYNC_BOOSTS_REPOSTS value '%s', using default true: %v", syncBoostsStr, err)
		syncBoosts = true
	}

	// Read SuppressNoNewPostsLogs env var (default to false)
	suppressLogsStr := getEnv("SUPPRESS_NO_NEW_POSTS_LOGS", "false")
	suppressLogs, err := strconv.ParseBool(suppressLogsStr)
	if err != nil {
		log.Printf("Invalid SUPPRESS_NO_NEW_POSTS_LOGS value '%s', using default false: %v", suppressLogsStr, err)
		suppressLogs = false
	}

	// Read SyncReplies env var (default to true)
	syncRepliesStr := getEnv("SYNC_REPLIES", "true")
	syncReplies, err := strconv.ParseBool(syncRepliesStr)
	if err != nil {
		log.Printf("Invalid SYNC_REPLIES value '%s', using default true: %v", syncRepliesStr, err)
		syncReplies = true
	}

	return &Config{
		DatabasePath:           getEnv("DATABASE_PATH", "fediversa.db"),
		SyncInterval:           time.Duration(intervalMinutes) * time.Minute,
		ListenAddr:             getEnv("LISTEN_ADDR", ":8080"),
		MastodonServer:         getEnv("MASTODON_SERVER", ""), // Must be provided by user
		MastodonClientID:       getEnv("MASTODON_CLIENT_ID", ""),
		MastodonClientSecret:   getEnv("MASTODON_CLIENT_SECRET", ""),
		BlueskyIdentifier:      getEnv("BLUESKY_IDENTIFIER", ""),            // Will likely be stored in DB later
		BlueskyPassword:        getEnv("BLUESKY_PASSWORD", ""),              // Will likely be stored in DB later
		BaseURL:                getEnv("BASE_URL", "http://localhost:8080"), // Important for OAuth
		SyncBoostsReposts:      syncBoosts,
		SuppressNoNewPostsLogs: suppressLogs,
		SyncReplies:            syncReplies,
	}
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
