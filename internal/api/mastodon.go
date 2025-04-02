package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fediversa/internal/config"
	"fediversa/internal/logging"
	"fediversa/internal/models"

	"github.com/mattn/go-mastodon"
	"golang.org/x/oauth2"
)

// MastodonClient wraps the go-mastodon client and adds configuration.
type MastodonClient struct {
	client *mastodon.Client
	cfg    *config.Config
	// Add other necessary fields, e.g., for storing user session info if needed
}

// NewMastodonClient creates a new Mastodon API client.
func NewMastodonClient(cfg *config.Config) *MastodonClient {
	// Use direct fields from config.Config
	client := mastodon.NewClient(&mastodon.Config{
		Server:       cfg.MastodonServer,
		ClientID:     cfg.MastodonClientID,
		ClientSecret: cfg.MastodonClientSecret,
	})
	return &MastodonClient{client: client, cfg: cfg}
}

// SetUserCredentials sets the access token for the authenticated user.
func (msc *MastodonClient) SetUserCredentials(accessToken string) {
	msc.client.Config.AccessToken = accessToken
	logging.Info("Mastodon access token set.")
}

// checkAuth verifies if the client has an access token.
func (msc *MastodonClient) checkAuth() error {
	if msc.client.Config.AccessToken == "" {
		return fmt.Errorf("mastodon client not authenticated: missing access token")
	}
	return nil
}

// Authenticate initiates the OAuth2 flow (Placeholder - real implementation is complex).
func (msc *MastodonClient) Authenticate(ctx context.Context, code string) (*oauth2.Token, error) {
	// Use direct fields from config.Config
	redirectURL := strings.TrimRight(msc.cfg.BaseURL, "/") + "/auth/mastodon/callback"
	logging.Info("Mastodon OAuth: Using RedirectURL: %s", redirectURL) // Log the URL

	conf := oauth2.Config{
		ClientID:     msc.cfg.MastodonClientID,
		ClientSecret: msc.cfg.MastodonClientSecret,
		Scopes:       []string{"read", "write", "follow"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", msc.cfg.MastodonServer),
			TokenURL: fmt.Sprintf("%s/oauth/token", msc.cfg.MastodonServer),
		},
		RedirectURL: redirectURL, // Use the logged and corrected URL
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		// Log the specific error before returning
		logging.Error("Mastodon OAuth token exchange failed: %v", err)
		return nil, fmt.Errorf("failed to exchange oauth code: %w", err)
	}

	msc.SetUserCredentials(token.AccessToken)
	logging.Info("Successfully obtained Mastodon access token.")
	return token, nil
}

// GetCurrentUserAccount retrieves the account details for the currently authenticated user.
func (msc *MastodonClient) GetCurrentUserAccount(ctx context.Context) (*mastodon.Account, error) {
	if err := msc.checkAuth(); err != nil {
		return nil, err
	}
	// Call the correct underlying method found in accounts.go
	return msc.client.GetAccountCurrentUser(ctx)
}

// FetchAccountStatuses fetches statuses for the specified user ID.
func (msc *MastodonClient) FetchAccountStatuses(ctx context.Context, userID string, pg *mastodon.Pagination) ([]*mastodon.Status, error) {
	if err := msc.checkAuth(); err != nil {
		return nil, err
	}
	mastoUserID := mastodon.ID(userID) // Convert string UserID to mastodon.ID
	// Pass the pagination pointer directly
	return msc.client.GetAccountStatuses(ctx, mastoUserID, pg)
}

// FetchTimeline fetches the user's home timeline.
func (msc *MastodonClient) FetchTimeline(ctx context.Context, userID string, sinceID *string) ([]*mastodon.Status, error) {
	if err := msc.checkAuth(); err != nil {
		return nil, err
	}

	pg := mastodon.Pagination{}
	if sinceID != nil && *sinceID != "" {
		pg.SinceID = mastodon.ID(*sinceID)
	}

	limit := int64(20)
	limitStr := os.Getenv("MASTODON_FETCH_LIMIT")
	if limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			limit = l
			logging.Info("Using custom Mastodon fetch limit: %d", limit)
		}
	}
	pg.Limit = limit // Assign int64 directly

	logging.Info("Fetching Mastodon timeline for user %s, since_id: %v, limit: %d", userID, pg.SinceID, pg.Limit)

	statuses, err := msc.client.GetTimelineHome(ctx, &pg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Mastodon home timeline: %w", err)
	}
	logging.Info("Fetched %d statuses from Mastodon timeline", len(statuses))
	return statuses, nil
}

// UploadBlob uploads media data and returns the attachment details.
func (msc *MastodonClient) UploadBlob(ctx context.Context, data []byte, contentType string, filename string) (*mastodon.Attachment, error) {
	if err := msc.checkAuth(); err != nil {
		return nil, err
	}

	logging.Info("Uploading blob to Mastodon, size: %d, filename: %s", len(data), filename)

	tempFile, err := os.CreateTemp("", "mastodon-upload-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for Mastodon upload: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("failed to write data to temp file: %w", err)
	}

	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("failed to seek temp file: %w", err)
	}

	// Correct call: UploadMediaFromReader only needs context and reader.
	attachment, err := msc.client.UploadMediaFromReader(ctx, tempFile)
	tempFile.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to upload media to Mastodon: %w", err)
	}

	logging.Info("Blob uploaded successfully to Mastodon: ID %s, URL: %s", attachment.ID, attachment.URL)
	return attachment, nil
}

// Post creates a new status (toot) on Mastodon.
func (msc *MastodonClient) Post(ctx context.Context, text string, media []*models.MediaAttachment, replyToID mastodon.ID) (string, error) {
	if err := msc.checkAuth(); err != nil {
		return "", err
	}

	logging.Info("Attempting to post to Mastodon: %s", text)

	toot := &mastodon.Toot{
		Status: text,
		// Visibility: mastodon.VisibilityPublic, // Default is usually public
	}

	// Add reply ID if provided
	if replyToID != "" {
		toot.InReplyToID = replyToID
		logging.Info("Posting as reply to Mastodon status ID: %s", replyToID)
	}

	if len(media) > 0 {
		logging.Info("Processing %d media attachments for Mastodon post", len(media))
		var mediaIDs []mastodon.ID
		for _, m := range media {
			if m.Attachment == nil {
				logging.Warn("Skipping media attachment with nil Mastodon attachment")
				continue
			}
			mastoAttach, ok := m.Attachment.(*mastodon.Attachment)
			if !ok {
				logging.Error("Media attachment is not of expected type *mastodon.Attachment")
				return "", fmt.Errorf("invalid attachment type for media")
			}
			mediaIDs = append(mediaIDs, mastoAttach.ID)
			logging.Info("Added media ID %s to Mastodon post", mastoAttach.ID)
		}
		toot.MediaIDs = mediaIDs
	}

	status, err := msc.client.PostStatus(ctx, toot)
	if err != nil {
		logging.Error("Failed to post status to Mastodon: %v", err)
		return "", fmt.Errorf("failed to post status to Mastodon: %w", err)
	}

	logging.Info("Successfully posted status to Mastodon: ID %s, URL: %s", status.ID, status.URL)
	return string(status.ID), nil
}

// DownloadMedia downloads media from a given URL to a temporary file in the specified directory.
// It returns the full path to the downloaded file and a cleanup function.
// The cleanup function should be called (e.g., using defer) to remove the temporary file.
func (msc *MastodonClient) DownloadMedia(ctx context.Context, mediaURL string, downloadDir string) (filePath string, cleanup func(), err error) {
	logging.Info("Downloading media from URL: %s", mediaURL)

	// Use a default HTTP client for downloading external URLs
	// We might not need authentication for this, assuming media URLs are public.
	// TODO: Confirm if Mastodon media URLs require authentication.
	client := http.DefaultClient

	req, err := http.NewRequestWithContext(ctx, "GET", mediaURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request for media URL %s: %w", mediaURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to download media from %s: %w", mediaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("failed to download media from %s: status code %d", mediaURL, resp.StatusCode)
	}

	// Create the download directory if it doesn't exist
	if err := os.MkdirAll(downloadDir, 0750); err != nil {
		return "", nil, fmt.Errorf("failed to create download directory %s: %w", downloadDir, err)
	}

	// Create a temporary file in the download directory
	// Extract filename from URL or use a random name
	fileName := extractFileName(mediaURL)
	tempFile, err := os.CreateTemp(downloadDir, "mastodon-*-"+fileName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file in %s: %w", downloadDir, err)
	}
	filePath = tempFile.Name()

	// Define cleanup function (closes file and removes it)
	cleanup = func() {
		_ = tempFile.Close()
		_ = os.Remove(filePath)
		logging.Info("Cleaned up temporary media file: %s", filePath)
	}

	// Copy the response body to the temporary file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		cleanup() // Clean up immediately on error
		return "", nil, fmt.Errorf("failed to save media to %s: %w", filePath, err)
	}

	// Close the file explicitly before returning, as the caller might use it immediately
	if err := tempFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close temporary file %s: %w", filePath, err)
	}

	logging.Info("Media downloaded successfully to: %s", filePath)
	return filePath, cleanup, nil
}

// extractFileName tries to get a reasonable filename from a URL path.
func extractFileName(mediaURL string) string {
	u, err := url.Parse(mediaURL)
	if err != nil {
		return "downloaded_media"
	}
	// Get the last part of the path
	base := filepath.Base(u.Path)
	// Remove query string if present in the base (though unlikely for direct media URLs)
	base = strings.Split(base, "?")[0]
	if base == "" || base == "." || base == "/" {
		return "downloaded_media"
	}
	return base
}
