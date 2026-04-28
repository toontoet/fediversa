package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"fediversa/internal/api"
	"fediversa/internal/config"
	"fediversa/internal/database"
	"fediversa/internal/logging"
	// Import other necessary internal packages like database, api later
)

// Server holds the dependencies for the web server.
type Server struct {
	Config         *config.Config
	DB             *database.DB
	MastodonClient *api.MastodonClient
	BlueskyClient  *api.BlueskyClient
	httpServer     *http.Server
}

// NewServer creates a new Server instance.
func NewServer(cfg *config.Config, db *database.DB, mc *api.MastodonClient, bc *api.BlueskyClient) *Server {
	return &Server{
		Config:         cfg,
		DB:             db,
		MastodonClient: mc,
		BlueskyClient:  bc,
	}
}

// Start runs the HTTP server in a goroutine.
func (s *Server) Start() {
	// Create handler instance with dependencies
	h := NewHandler(s.Config, s.DB, s.MastodonClient, s.BlueskyClient)

	// Setup routes
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	handler := h.authMiddleware(mux)

	s.httpServer = &http.Server{
		Addr:    s.Config.ListenAddr,
		Handler: handler,
		// TODO: Add timeouts for production readiness
		ReadTimeout:  15 * time.Second, // Increased slightly
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logging.Info("Starting web server on %s", s.Config.ListenAddr)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Fatal("Web server failed: %v", err)
		}
	}()
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	logging.Info("Shutting down web server...")
	if s.httpServer != nil {
		// Add a timeout context for shutdown
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
	return nil // No server was started
}

func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	if h.Config.WebAuthPassword == "" {
		logging.Warn("WEB_AUTH_PASSWORD is not set; web UI is accessible without authentication.")
		return next
	}

	username := h.Config.WebAuthUsername
	if username == "" {
		username = "admin"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || !constantTimeEqual(user, username) || !constantTimeEqual(password, h.Config.WebAuthPassword) {
			w.Header().Set("WWW-Authenticate", `Basic realm="FediVersa", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}
