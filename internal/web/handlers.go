package web

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"fediversa/internal/api"
	"fediversa/internal/config"
	"fediversa/internal/database"
	"fediversa/internal/logging"
	"fediversa/internal/models"

	// Import generated templates
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	Config         *config.Config
	DB             *database.DB
	MastodonClient *api.MastodonClient
	BlueskyClient  *api.BlueskyClient
	templates      *template.Template
	sessionStore   *sessions.CookieStore
}

// PageData holds the data passed to HTML templates.
type PageData struct {
	Accounts     AccountStatus
	Stats        StatsData
	FlashMessage string
	FlashIsError bool
}

// AccountStatus holds the status of linked accounts.
type AccountStatus struct {
	Mastodon *models.Account
	Bluesky  *models.Account
}

// StatsData holds the statistics to display.
type StatsData struct {
	TotalSyncedPosts int
	LastMastodonSync sql.NullTime
	LastBlueskySync  sql.NullTime
}

const mastodonStateCookie = "fediversa-mastodon-oauth-state"
const mastodonScopes = "read write follow"

// NewHandler creates a new Handler instance.
func NewHandler(cfg *config.Config, db *database.DB, mc *api.MastodonClient, bc *api.BlueskyClient) *Handler {
	// Initialize templates
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		logging.Fatal("Failed to parse templates: %v", err)
	}

	// Initialize session store
	key := []byte("super-secret-key-replace-this!") // WARNING: Replace with a secure random key!
	store := sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
		// Secure: true, // Enable this when using HTTPS
		// SameSite: http.SameSiteLaxMode,
	}

	// Register the type used in flash messages with gob
	gob.Register(map[string]interface{}{})

	return &Handler{
		Config:         cfg,
		DB:             db,
		MastodonClient: mc,
		BlueskyClient:  bc,
		templates:      tmpl,
		sessionStore:   store,
	}
}

// RegisterRoutes sets up the HTTP routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/auth/mastodon/callback", h.handleMastodonCallback)
	mux.HandleFunc("POST /auth/mastodon/login", h.handleMastodonLoginStart) // Trigger login - Restore correct handler
	mux.HandleFunc("POST /auth/bluesky/login", h.handleBlueskyLogin)
	// TODO: Add routes for logout/unlink?
	// mux.HandleFunc("/debug/bluesky/refresh", h.handleDebugBlueskyRefresh) // REMOVE ROUTE
}

// handleIndex displays the main status page.
func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Fetch data from database
	mastodonAcc, errMasto := h.DB.GetAccountByService("mastodon")
	if errMasto != nil {
		logging.Error("Failed to get Mastodon account: %v", errMasto)
		// Don't fail the page load, just show as not linked
	}
	blueskyAcc, errBsky := h.DB.GetAccountByService("bluesky")
	if errBsky != nil {
		logging.Error("Failed to get Bluesky account: %v", errBsky)
		// Don't fail the page load
	}

	totalSynced, errTotal := h.DB.GetTotalSyncedPosts()
	if errTotal != nil {
		logging.Error("Failed to get total synced posts: %v", errTotal)
	}
	lastMastoSync, errLastMasto := h.DB.GetLastSyncTime("mastodon")
	if errLastMasto != nil {
		logging.Error("Failed to get last Mastodon sync time: %v", errLastMasto)
	}
	lastBskySync, errLastBsky := h.DB.GetLastSyncTime("bluesky")
	if errLastBsky != nil {
		logging.Error("Failed to get last Bluesky sync time: %v", errLastBsky)
	}

	// Get flash message from session
	session, _ := h.sessionStore.Get(r, "fediversa-session")
	flashMessage := ""
	flashIsError := false
	if flashes := session.Flashes(); len(flashes) > 0 {
		if fm, ok := flashes[0].(map[string]interface{}); ok {
			flashMessage = fm["message"].(string)
			flashIsError = fm["isError"].(bool)
		}
	}
	errSave := session.Save(r, w) // Save session to clear flash
	if errSave != nil {
		logging.Error("Failed to save session after reading flash: %v", errSave)
	}

	data := PageData{
		Accounts: AccountStatus{
			Mastodon: mastodonAcc,
			Bluesky:  blueskyAcc,
		},
		Stats: StatsData{
			TotalSyncedPosts: totalSynced,
			LastMastodonSync: lastMastoSync,
			LastBlueskySync:  lastBskySync,
		},
		FlashMessage: flashMessage,
		FlashIsError: flashIsError,
	}

	// Render template
	err := h.templates.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		logging.Error("Failed to render index template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// getMastodonOAuthConfig creates an oauth2.Config for Mastodon
func (h *Handler) getMastodonOAuthConfig() (*oauth2.Config, error) {
	if h.Config.MastodonServer == "" || h.Config.MastodonClientID == "" || h.Config.MastodonClientSecret == "" {
		return nil, fmt.Errorf("mastodon server, client ID, or client secret not configured")
	}

	// Construct the auth and token URLs based on the server address
	baseURL, err := url.Parse(h.Config.MastodonServer)
	if err != nil {
		return nil, fmt.Errorf("invalid mastodon server URL: %w", err)
	}
	authURL := *baseURL
	authURL.Path = "/oauth/authorize"
	tokenURL := *baseURL
	tokenURL.Path = "/oauth/token"

	redirectURL := strings.TrimRight(h.Config.BaseURL, "/") + "/auth/mastodon/callback"

	return &oauth2.Config{
		ClientID:     h.Config.MastodonClientID,
		ClientSecret: h.Config.MastodonClientSecret,
		Scopes:       strings.Split(mastodonScopes, " "),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
		RedirectURL: redirectURL,
	}, nil
}

// handleMastodonLoginStart initiates the OAuth flow.
func (h *Handler) handleMastodonLoginStart(w http.ResponseWriter, r *http.Request) {
	// Method check is handled by new router pattern "POST /..."
	oauthCfg, err := h.getMastodonOAuthConfig()
	if err != nil {
		logging.Error("Mastodon OAuth config error: %v", err)
		h.setFlash(w, r, "Mastodon integration not configured correctly.", true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Generate state parameter for CSRF protection
	stateBytes := make([]byte, 32)
	_, err = rand.Read(stateBytes)
	if err != nil {
		logging.Error("Failed to generate OAuth state: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Store state in a short-lived cookie
	http.SetCookie(w, &http.Cookie{
		Name:     mastodonStateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		// Secure: true, // Enable when using HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect user to Mastodon authorization page
	authURL := oauthCfg.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleMastodonCallback handles the redirect back from Mastodon.
func (h *Handler) handleMastodonCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "OAuth callback missing code parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	token, err := h.MastodonClient.Authenticate(ctx, code)
	if err != nil {
		logging.Error("Mastodon OAuth token exchange failed: %v", err)
		http.Error(w, fmt.Sprintf("Mastodon authentication failed: %v", err), http.StatusInternalServerError)
		return
	}

	// At this point, the MastodonClient instance (h.MastodonClient)
	// should have the user's token set internally by the Authenticate method.
	// We now need to get the user's account details to store them.

	// Use the correct method to get the current user's account details
	mastoAccount, err := h.MastodonClient.GetCurrentUserAccount(ctx)
	if err != nil {
		logging.Error("Failed to get Mastodon account details after auth: %v", err)
		http.Error(w, "Failed to retrieve Mastodon account details", http.StatusInternalServerError)
		return
	}

	// Store account details in the database
	account := &models.Account{
		Service:      "mastodon",
		UserID:       string(mastoAccount.ID), // Convert mastodon.ID to string
		Username:     mastoAccount.Acct,
		AccessToken:  sql.NullString{String: token.AccessToken, Valid: true},
		RefreshToken: sql.NullString{String: token.RefreshToken, Valid: true},
		ExpiresAt:    sql.NullTime{Time: token.Expiry, Valid: !token.Expiry.IsZero()},
	}

	if err := h.DB.SaveAccount(account); err != nil {
		logging.Error("Failed to save Mastodon account details: %v", err)
		http.Error(w, "Failed to save account details", http.StatusInternalServerError)
		return
	}

	logging.Info("Successfully linked Mastodon account: %s", mastoAccount.Acct)

	// Redirect back to the home page or a success page
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleBlueskyLogin handles the form submission for Bluesky login.
func (h *Handler) handleBlueskyLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	identifier := r.FormValue("identifier")
	password := r.FormValue("password")

	if identifier == "" || password == "" {
		h.setFlash(w, r, "Identifier and App Password are required.", true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Attempt to authenticate using the Bluesky client
	account, err := h.BlueskyClient.Authenticate(r.Context(), identifier, password)
	if err != nil {
		logging.Error("Bluesky authentication failed during web login: %v", err)
		h.setFlash(w, r, "Bluesky login failed. Check credentials and App Password.", true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Save the authenticated account details (including session tokens) to the DB
	err = h.DB.SaveAccount(account)
	if err != nil {
		logging.Error("Failed to save Bluesky account after login: %v", err)
		h.setFlash(w, r, "Bluesky login successful, but failed to save account details.", true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Set success flash message and redirect
	h.setFlash(w, r, "Bluesky account linked successfully!", false)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// setFlash adds a flash message to the session.
func (h *Handler) setFlash(w http.ResponseWriter, r *http.Request, message string, isError bool) {
	session, _ := h.sessionStore.Get(r, "fediversa-session")
	flash := map[string]interface{}{
		"message": message,
		"isError": isError,
	}
	session.AddFlash(flash)
	err := session.Save(r, w)
	if err != nil {
		logging.Error("Failed to save session while setting flash: %v", err)
		// Handle error appropriately, maybe log or return an error response
	}
}

// handleDebugBlueskyRefresh forces a token refresh for debugging purposes
/*
func (h *Handler) handleDebugBlueskyRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get Bluesky account from database
	acc, err := h.DB.GetAccountByService("bluesky")
	if err != nil {
		logging.Error("Failed to get Bluesky account for debug refresh: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		http.Error(w, "Bluesky account not found", http.StatusNotFound)
		return
	}

	// Set the session in the client
	if err := h.BlueskyClient.SetSession(acc); err != nil {
		logging.Error("Failed to set Bluesky session for debug refresh: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Force refresh the session
	_, refreshed, err := h.BlueskyClient.RefreshSessionIfNeeded(r.Context(), acc, true)
	if err != nil {
		logging.Error("Debug refresh failed: %v", err)
		http.Error(w, fmt.Sprintf("Refresh failed: %v", err), http.StatusInternalServerError)
		return
	}

	if refreshed {
		// Save the updated account details
		if err := h.DB.SaveAccount(acc); err != nil {
			logging.Error("Failed to save updated account after debug refresh: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Redirect back to index with success message
	http.Redirect(w, r, "/?message=Debug refresh completed", http.StatusSeeOther)
}
*/
