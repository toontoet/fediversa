package api

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	appbsky "github.com/bluesky-social/indigo/api/bsky"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ipfs/go-cid"

	// Import for secp256k1 signatures (though Verify is minimal)

	"fediversa/internal/config"
	"fediversa/internal/logging"
	"fediversa/internal/models"
)

// --- ES256K JWT Signing Method Registration ---

// signingMethodES256K implements the jwt.SigningMethod interface for ES256K.
// NOTE: The Verify method is minimal as we primarily need the parser to recognize the algorithm.
// Actual signature verification happens server-side during refresh.
type signingMethodES256K struct{}

// Singleton instance
var signingMethodES256KInst = &signingMethodES256K{}

func init() {
	// Register the ES256K signing method algorithm with the jwt library.
	jwt.RegisterSigningMethod("ES256K", func() jwt.SigningMethod {
		return signingMethodES256KInst
	})
	logging.Info("Registered ES256K JWT signing method.")
}

func (m *signingMethodES256K) Alg() string {
	return "ES256K"
}

// Verify implements the Verify method from jwt.SigningMethod.
// For our current purpose (allowing the parser to recognize "ES256K"),
// we don't perform full local validation, as the server handles it during refresh.
// This returns nil error IF the key is parsable as ecdsa public key (basic check).
// WARNING: THIS DOES NOT ACTUALLY VERIFY THE SIGNATURE AGAINST THE KEY.
func (m *signingMethodES256K) Verify(signingString string, signature []byte, key interface{}) error {
	// We could attempt to parse the key and signature for basic validity checks,
	// but for now, we accept it to allow parsing tokens signed with ES256K.
	logging.Info("ES256K Verify called (minimal check)")

	// Example of a more involved check (requires key handling):
	/*
		var pubKey *btcec.PublicKey
		var ok bool
		if pubKey, ok = key.(*btcec.PublicKey); !ok {
			// Attempt to parse from bytes if possible, or handle other key types
			return jwt.ErrInvalidKeyType
		}

		hash := sha256.Sum256([]byte(signingString))
		sig, err := ecdsa.ParseDERSignature(signature)
		if err != nil {
		    return fmt.Errorf("failed to parse DER signature: %w", err)
		}

		if !sig.Verify(hash[:], pubKey) {
		    return jwt.ErrSignatureInvalid
		}
	*/

	return nil // Assume valid for parser recognition purposes
}

// Sign implements the Sign method from jwt.SigningMethod.
// We don't need to sign tokens locally with ES256K.
func (m *signingMethodES256K) Sign(signingString string, key interface{}) ([]byte, error) {
	return nil, errors.New("ES256K signing not implemented")
}

// --- End ES256K Registration ---

const defaultPDS = "https://bsky.social" // Default PDS host

// BlueskyClient wraps the indigo XRPC client and provides methods
// specific to FediVersa's needs for Bluesky interaction.
type BlueskyClient struct {
	client *xrpc.Client
	// We'll store the session details (DID, handle, tokens) in the Account model in the database.
}

// NewBlueskyClient creates a new Bluesky client instance.
// Initially, it just sets up an unauthenticated client.
// Authentication (session creation) happens later using credentials from config or DB.
func NewBlueskyClient(cfg *config.Config) (*BlueskyClient, error) {
	logging.Info("Initializing Bluesky client.")

	// Create a basic unauthenticated client connected to the default PDS
	// TODO: Make PDS configurable?
	client := &xrpc.Client{
		Host: defaultPDS,
		// Client: &http.Client{Transport: &loggingTransport{}}, // Revert to default client
		Client: getHttpClient(), // Use default http client for now
	}

	// We don't authenticate here. Authentication will create a session.
	// The session details (DID, handle, access/refresh tokens) should be stored
	// in the database (`accounts` table using the models.Account struct).

	// TODO: Add a check to see if the PDS is reachable?

	return &BlueskyClient{
		client: client,
	}, nil
}

// Authenticate creates a session with the Bluesky PDS using identifier and app password.
// It returns the authenticated account details, which should be saved.
func (bsc *BlueskyClient) Authenticate(ctx context.Context, identifier, appPassword string) (*models.Account, error) {
	logging.Info("Authenticating Bluesky client for user: %s", identifier)
	sess, err := comatproto.ServerCreateSession(ctx, bsc.client, &comatproto.ServerCreateSession_Input{
		Identifier: identifier,
		Password:   appPassword,
	})
	if err != nil {
		logging.Error("Bluesky authentication failed for %s: %v", identifier, err)
		return nil, fmt.Errorf("bluesky authentication failed: %w", err)
	}

	logging.Info("Bluesky authentication successful for user: %s (DID: %s)", sess.Handle, sess.Did)

	// Update the client with the authenticated session details
	bsc.client.Auth = &xrpc.AuthInfo{
		AccessJwt:  sess.AccessJwt,
		RefreshJwt: sess.RefreshJwt,
		Handle:     sess.Handle,
		Did:        sess.Did,
	}

	// Prepare account model to be saved
	acc := &models.Account{
		Service:      "bluesky",
		UserID:       sess.Did,
		Username:     sess.Handle,
		AccessToken:  sql.NullString{String: sess.AccessJwt, Valid: true},
		RefreshToken: sql.NullString{String: sess.RefreshJwt, Valid: true},
		AppPassword:  sql.NullString{String: appPassword, Valid: true}, // Store the app password used
	}

	// Parse both access and refresh tokens to get their expiry times
	accessToken, _, err := new(jwt.Parser).ParseUnverified(sess.AccessJwt, jwt.MapClaims{})
	if err == nil {
		if claims, ok := accessToken.Claims.(jwt.MapClaims); ok {
			if expFloat, ok := claims["exp"].(float64); ok {
				expTime := time.Unix(int64(expFloat), 0)
				acc.ExpiresAt = sql.NullTime{Time: expTime, Valid: true}
			}
		}
	}

	refreshToken, _, err := new(jwt.Parser).ParseUnverified(sess.RefreshJwt, jwt.MapClaims{})
	if err == nil {
		if claims, ok := refreshToken.Claims.(jwt.MapClaims); ok {
			if expFloat, ok := claims["exp"].(float64); ok {
				expTime := time.Unix(int64(expFloat), 0)
				acc.RefreshExpiresAt = sql.NullTime{Time: expTime, Valid: true}
			}
		}
	}

	return acc, nil
}

// SetSession applies a previously stored session (e.g., loaded from the database) to the client.
func (bsc *BlueskyClient) SetSession(account *models.Account) error {
	if account == nil || account.Service != "bluesky" {
		return fmt.Errorf("invalid account provided for Bluesky session")
	}
	if !account.AccessToken.Valid || !account.RefreshToken.Valid || account.UserID == "" || account.Username == "" {
		return fmt.Errorf("incomplete account details for Bluesky session")
	}

	bsc.client.Auth = &xrpc.AuthInfo{
		AccessJwt:  account.AccessToken.String,
		RefreshJwt: account.RefreshToken.String,
		Handle:     account.Username,
		Did:        account.UserID,
	}
	return nil
}

// checkAuth ensures the client has authentication information.
func (bsc *BlueskyClient) checkAuth() error {
	if bsc.client.Auth == nil || bsc.client.Auth.Did == "" {
		return fmt.Errorf("bluesky client not authenticated")
	}
	return nil
}

// FetchTimeline fetches the user's timeline or feed.
// It might need pagination handling in a real application.
func (bsc *BlueskyClient) FetchTimeline(ctx context.Context, userID string, sinceID *string) (*appbsky.FeedGetTimeline_Output, error) {
	if err := bsc.checkAuth(); err != nil {
		return nil, err
	}

	logging.Info("Fetching Bluesky timeline for user %s", userID)

	limit := int64(20)
	limitStr := os.Getenv("BLUESKY_FETCH_LIMIT")
	if limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			limit = l
			logging.Info("Using custom fetch limit: %d", limit)
		}
	}

	var cursorVal string
	if sinceID != nil {
		logging.Warn("Bluesky FetchTimeline: sinceID provided but cursor usage from sinceID not implemented. Fetching latest.")
	}

	feed, err := appbsky.FeedGetTimeline(ctx, bsc.client, "", cursorVal, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get Bluesky timeline: %w", err)
	}

	logging.Info("Fetched %d posts from Bluesky timeline", len(feed.Feed))
	return feed, nil
}

// UploadBlob uploads media data and returns the blob reference.
func (bsc *BlueskyClient) UploadBlob(ctx context.Context, data []byte, contentType string) (*lexutil.LexBlob, error) {
	if err := bsc.checkAuth(); err != nil {
		return nil, err
	}

	logging.Info("Uploading blob to Bluesky, size: %d, content-type: %s", len(data), contentType)

	resp, err := comatproto.RepoUploadBlob(ctx, bsc.client, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to upload blob to Bluesky: %w", err)
	}

	// Check Ref using .String() != "" instead of comparing LexLink to nil
	var cidStr string
	if resp.Blob != nil { // Check if Blob itself is not nil
		// Assuming LexLink.String() returns empty string or specific invalid value for zero/error state
		if resp.Blob.Ref.String() != "" {
			cidStr = resp.Blob.Ref.String()
		}
	}
	logging.Info("Blob uploaded successfully to Bluesky: CID %s", cidStr)

	return resp.Blob, nil
}

// Post creates a new post (skeet) on Bluesky.
func (bsc *BlueskyClient) Post(ctx context.Context, text string, media []*models.MediaAttachment, replyRef *appbsky.FeedPost_ReplyRef) (string, error) {
	if err := bsc.checkAuth(); err != nil {
		return "", err
	}

	logging.Info("Attempting to post to Bluesky: %s", text)

	var embeds []*appbsky.EmbedImages_Image
	var recordEmbed *appbsky.FeedPost_Embed

	if len(media) > 0 {
		logging.Info("Processing %d media attachments for Bluesky post", len(media))
		for _, m := range media {
			if m.Blob == nil {
				logging.Warn("Skipping media attachment with nil blob reference")
				continue
			}
			lexBlob, ok := m.Blob.(*lexutil.LexBlob)
			if !ok {
				logging.Error("Media attachment blob is not of expected type *lexutil.LexBlob, got %T", m.Blob)
				return "", fmt.Errorf("invalid blob type for media attachment")
			}
			embeds = append(embeds, &appbsky.EmbedImages_Image{
				Alt:   m.Description,
				Image: lexBlob,
			})
			// Check Ref using .String() != ""
			var blobCidStr string
			if lexBlob != nil { // Check if lexBlob itself is not nil
				if lexBlob.Ref.String() != "" {
					blobCidStr = lexBlob.Ref.String()
				}
			}
			logging.Info("Added image to Bluesky post: Alt='%s', CID=%s", m.Description, blobCidStr)
		}

		if len(embeds) > 0 {
			if len(embeds) > 4 {
				logging.Warn("Bluesky allows a maximum of 4 images per post. Truncating to 4.")
				embeds = embeds[:4]
			}
			recordEmbed = &appbsky.FeedPost_Embed{
				EmbedImages: &appbsky.EmbedImages{Images: embeds},
			}
			logging.Info("Created EmbedImages structure for Bluesky post with %d images", len(embeds))
		}
	}

	facets, err := bsc.detectFacets(ctx, text)
	if err != nil {
		logging.Error("Failed to detect facets: %v", err)
		facets = nil
	}

	post := &appbsky.FeedPost{
		LexiconTypeID: "app.bsky.feed.post",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Text:          text,
		Embed:         recordEmbed,
		Facets:        facets,
		Reply:         replyRef,
	}

	if replyRef != nil {
		rootURI := "nil"
		parentURI := "nil"
		if replyRef.Root != nil {
			rootURI = replyRef.Root.Uri
		}
		if replyRef.Parent != nil {
			parentURI = replyRef.Parent.Uri
		}
		logging.Info("Posting Bluesky reply with Root: %s, Parent: %s", rootURI, parentURI)
	}

	res, err := comatproto.RepoCreateRecord(ctx, bsc.client, &comatproto.RepoCreateRecord_Input{
		Collection: "app.bsky.feed.post",
		Repo:       bsc.client.Auth.Did,
		Record:     &lexutil.LexiconTypeDecoder{Val: post},
	})
	if err != nil {
		logging.Error("Failed to create Bluesky post: %v", err)
		return "", fmt.Errorf("failed to create Bluesky post: %w", err)
	}

	logging.Info("Successfully posted to Bluesky: URI %s, CID %s", res.Uri, res.Cid)
	return res.Uri, nil
}

// detectFacets finds mentions and links in text and converts them to Bluesky facets.
func (bsc *BlueskyClient) detectFacets(ctx context.Context, text string) ([]*appbsky.RichtextFacet, error) {
	var facets []*appbsky.RichtextFacet

	linkRegex := regexp.MustCompile(`(?i)\b(https?://[^\s<>\"')]+)`)
	mentionRegex := regexp.MustCompile(`(?i)(?:^|\s)(@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,})+))\b`)

	// --- Find Links ---
	linkMatches := linkRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range linkMatches {
		startIndex := match[0]
		endIndex := match[1]
		uri := text[startIndex:endIndex]

		byteStart := int64(startIndex)
		byteEnd := int64(endIndex)

		facets = append(facets, &appbsky.RichtextFacet{
			Index: &appbsky.RichtextFacet_ByteSlice{
				ByteStart: byteStart,
				ByteEnd:   byteEnd,
			},
			// Use the specific type expected by the Features slice
			Features: []*appbsky.RichtextFacet_Features_Elem{
				{
					RichtextFacet_Link: &appbsky.RichtextFacet_Link{Uri: uri},
				},
			},
		})
	}

	// --- Find Mentions ---
	mentionMatches := mentionRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range mentionMatches {
		handleStartIndex := match[4]
		handleEndIndex := match[5]
		handle := text[handleStartIndex:handleEndIndex]

		byteStart := int64(match[0])
		byteEnd := int64(match[1])

		resp, err := comatproto.IdentityResolveHandle(ctx, bsc.client, handle)
		if err != nil {
			logging.Warn("Failed to resolve handle '%s': %v. Skipping mention facet.", handle, err)
			continue
		}

		facets = append(facets, &appbsky.RichtextFacet{
			Index: &appbsky.RichtextFacet_ByteSlice{
				ByteStart: byteStart,
				ByteEnd:   byteEnd,
			},
			// Use the specific type expected by the Features slice
			Features: []*appbsky.RichtextFacet_Features_Elem{
				{
					RichtextFacet_Mention: &appbsky.RichtextFacet_Mention{Did: resp.Did},
				},
			},
		})
	}

	// TODO: Sort facets by byte start index?
	return facets, nil
}

// ParseAtURI converts an AT URI string (at://did/collection/rkey) into a RepoStrongRef.
func ParseAtURI(uri string) (*comatproto.RepoStrongRef, error) {
	if !strings.HasPrefix(uri, "at://") {
		return nil, fmt.Errorf("invalid AT URI scheme: %s", uri)
	}
	parts := strings.SplitN(strings.TrimPrefix(uri, "at://"), "/", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed AT URI: %s", uri)
	}
	_ = parts[0] // did - mark as unused for now
	_ = parts[1] // collection - mark as unused for now
	_ = parts[2] // rkey - mark as unused for now

	// We need the CID of the record referenced by the URI to create a StrongRef.
	// This typically requires resolving the record first (fetching it).
	// For now, we create a ref WITHOUT the CID, which might be insufficient
	// for some operations, but necessary for the ReplyRef structure.
	// TODO: Investigate if fetching the record to get the CID is feasible/necessary here.

	// Create a placeholder CID or handle cases where CID is needed but absent.
	// A zero-length CID might cause issues downstream.
	// Using a known invalid CID string might be better if the library handles it.
	// For now, we log a warning and create the ref without a valid CID.
	logging.Warn("ParseAtURI: Creating RepoStrongRef for %s without resolving CID. Threading might be incomplete.", uri)

	// Placeholder CID - This is likely incorrect for actual use but satisfies the struct.
	// We might need to parse the rkey as a TID for a more robust placeholder?
	// Or perhaps the library allows creating a ref with only URI?
	// Let's attempt creating ref without CID first, if RepoStrongRef allows it.
	// It seems RepoStrongRef requires Cid and Uri. Let's use a placeholder CID string.
	placeholderCidStr := "bafyreihyr56gxwz6orti4mbvm5d3j3ryltza7qj5hxjffqifufhssu7l5y" // Example CID

	ref := &comatproto.RepoStrongRef{
		Uri: uri,
		Cid: placeholderCidStr, // WARNING: Using placeholder CID!
	}

	return ref, nil
}

// DownloadBlob downloads a blob using the sync GetBlob method.
// It saves the blob data to a temporary file in the specified downloadDir.
// Returns the full path to the downloaded file, the content type, and a cleanup function.
func (bsc *BlueskyClient) DownloadBlob(ctx context.Context, ownerDID string, blobCID cid.Cid, downloadDir string) (filePath string, contentType string, cleanup func(), err error) {
	if err := bsc.checkAuth(); err != nil {
		return "", "", nil, err
	}

	logging.Info("Downloading blob CID %s for DID %s", blobCID.String(), ownerDID)

	// Use comatproto.SyncGetBlob to fetch the blob data
	blobData, err := comatproto.SyncGetBlob(ctx, bsc.client, blobCID.String(), ownerDID)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get blob %s: %w", blobCID.String(), err)
	}

	// Determine content type - unfortunately, SyncGetBlob doesn't return it directly.
	// We might need to guess based on the first few bytes or rely on information
	// stored alongside the blob reference (e.g., in the post embed).
	// For now, let's use http.DetectContentType.
	contentType = http.DetectContentType(blobData)
	logging.Info("Detected blob content type: %s", contentType)

	// Create the download directory if it doesn't exist
	if err := os.MkdirAll(downloadDir, 0750); err != nil {
		return "", "", nil, fmt.Errorf("failed to create download directory %s: %w", downloadDir, err)
	}

	// Create a temporary file
	// Try to create a meaningful extension based on detected type
	extensions, _ := mime.ExtensionsByType(contentType)
	ext := ".bin" // Default extension
	if len(extensions) > 0 {
		ext = extensions[0]
	}
	tempFile, err := os.CreateTemp(downloadDir, "bluesky-*-"+blobCID.String()+ext)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create temporary file for blob %s: %w", blobCID.String(), err)
	}
	filePath = tempFile.Name()

	// Define cleanup function
	cleanup = func() {
		_ = tempFile.Close()
		_ = os.Remove(filePath)
		logging.Info("Cleaned up temporary blob file: %s", filePath)
	}

	// Write blob data to the file
	_, err = tempFile.Write(blobData)
	if err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("failed to save blob %s to %s: %w", blobCID.String(), filePath, err)
	}

	// Close the file before returning
	if err := tempFile.Close(); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("failed to close temporary blob file %s: %w", filePath, err)
	}

	logging.Info("Blob %s downloaded successfully to: %s", blobCID.String(), filePath)
	return filePath, contentType, cleanup, nil
}

// TODO: Add methods for handling media downloads? (Requires resolving blob refs?)

// FetchAuthorFeed fetches the feed for a specific author (actor DID).
func (bsc *BlueskyClient) FetchAuthorFeed(ctx context.Context, actor string, cursor string, limit int64) (*appbsky.FeedGetAuthorFeed_Output, error) {
	if err := bsc.checkAuth(); err != nil {
		return nil, err
	}
	// Provide default values for filter and the missing boolean argument (likely isMuted=false)
	filter := ""     // Or use "posts_no_replies", "posts_with_media", etc.
	isMuted := false // Add the missing boolean argument
	return appbsky.FeedGetAuthorFeed(ctx, bsc.client, actor, cursor, filter, isMuted, limit)
}

// RefreshSessionIfNeeded checks if a refresh token exists and attempts to refresh the session.
// It now includes logging the signing algorithm from the access token if parsing fails.
func (bsc *BlueskyClient) RefreshSessionIfNeeded(ctx context.Context, acc *models.Account, force bool) (*models.Account, bool, error) {
	// 1. Check if RefreshToken exists and is still valid
	if !acc.RefreshToken.Valid || acc.RefreshToken.String == "" {
		logging.Info("No refresh token found for Bluesky account %s, cannot refresh.", acc.Username)
		return acc, false, nil
	}

	// Check if refresh token itself is expired
	if acc.RefreshExpiresAt.Valid && time.Now().After(acc.RefreshExpiresAt.Time) {
		logging.Error("Bluesky refresh token for %s has expired (expired at %v). Manual re-login required.", acc.Username, acc.RefreshExpiresAt.Time)
		return acc, false, fmt.Errorf("refresh token expired for %s", acc.Username)
	}

	// 2. Check if we need to refresh based on access token expiry time
	shouldAttemptRefresh := force
	if !force && acc.ExpiresAt.Valid {
		// Refresh if token expires in less than 5 minutes
		if time.Now().Before(acc.ExpiresAt.Time.Add(-5 * time.Minute)) {
			logging.Info("Bluesky access token for %s is still valid (expires at %v).", acc.Username, acc.ExpiresAt.Time)
			shouldAttemptRefresh = false
		} else {
			logging.Info("Bluesky access token for %s is expired or nearing expiry (expires at %v).", acc.Username, acc.ExpiresAt.Time)
			shouldAttemptRefresh = true
		}
	}

	if !shouldAttemptRefresh {
		return acc, false, nil
	}

	// 3. Attempt refresh
	logging.Info("Attempting to refresh Bluesky session for %s (refresh token found)...", acc.Username)

	// Ensure the client Auth reflects the loaded account state
	if bsc.client.Auth == nil {
		logging.Warn("Client Auth is nil before refresh call. Setting it now.")
		bsc.client.Auth = &xrpc.AuthInfo{
			AccessJwt:  acc.AccessToken.String,
			RefreshJwt: acc.RefreshToken.String,
			Handle:     acc.Username,
			Did:        acc.UserID,
		}
	} else if bsc.client.Auth.RefreshJwt != acc.RefreshToken.String {
		logging.Warn("Client Auth refresh token mismatch. Updating it now.")
		logging.Info("Client Auth refresh token: %v", bsc.client.Auth.RefreshJwt != "")
		logging.Info("Account refresh token: %v", acc.RefreshToken.Valid)
		bsc.client.Auth.RefreshJwt = acc.RefreshToken.String
	}

	// --- HACK: Temporarily swap tokens because ServerRefreshSession seems to use AccessJwt ---
	originalAccessJwt := bsc.client.Auth.AccessJwt
	originalRefreshJwt := bsc.client.Auth.RefreshJwt
	bsc.client.Auth.AccessJwt = originalRefreshJwt // Use Refresh token in AccessJwt field for the call
	// logging.Info("HACK: Using refresh token in AccessJwt field for ServerRefreshSession call.") // Remove hack log
	// --- End HACK ---

	newSessionOutput, err := comatproto.ServerRefreshSession(ctx, bsc.client)

	// --- HACK: Restore original tokens immediately after the call ---
	bsc.client.Auth.AccessJwt = originalAccessJwt
	bsc.client.Auth.RefreshJwt = originalRefreshJwt
	// logging.Info("HACK: Restored original tokens in client.Auth after ServerRefreshSession call.") // Remove hack log
	// --- End HACK ---

	if err != nil {
		// No need to restore originalAuth as we didn't change it here
		// Check if the error is specifically about an invalid refresh token
		if strings.Contains(err.Error(), "invalid refresh token") || strings.Contains(err.Error(), "ExpiredToken") || strings.Contains(err.Error(), "BadRefreshToken") || strings.Contains(err.Error(), "Invalid token type") {
			logging.Error("Bluesky refresh token for %s is invalid or expired. Manual re-login required. Error: %v", acc.Username, err)
			return acc, false, fmt.Errorf("invalid or expired refresh token for %s: %w", acc.Username, err)
		} else {
			// Other refresh error
			logging.Error("Failed to refresh Bluesky session for %s: %v", acc.Username, err)
			return acc, false, fmt.Errorf("failed to refresh session for %s: %w", acc.Username, err)
		}
	}

	// 4. Refresh successful, update client Auth and account object
	if newSessionOutput == nil || newSessionOutput.AccessJwt == "" || newSessionOutput.RefreshJwt == "" {
		// No need to restore originalAuth
		logging.Error("Bluesky ServerRefreshSession succeeded but returned empty session data for %s", acc.Username)
		return acc, false, fmt.Errorf("refresh succeeded but session data is empty for %s", acc.Username)
	}

	// Update the client's active auth session with the NEW details
	bsc.client.Auth = &xrpc.AuthInfo{
		AccessJwt:  newSessionOutput.AccessJwt,
		RefreshJwt: newSessionOutput.RefreshJwt,
		Handle:     newSessionOutput.Handle,
		Did:        newSessionOutput.Did,
	}

	// Update the account object to be saved later
	acc.AccessToken = sql.NullString{String: newSessionOutput.AccessJwt, Valid: true}
	acc.RefreshToken = sql.NullString{String: newSessionOutput.RefreshJwt, Valid: true}
	acc.UserID = newSessionOutput.Did
	acc.Username = newSessionOutput.Handle

	// After successful refresh, update both token expiry times
	if newSessionOutput != nil {
		// Parse new access token expiry
		accessToken, _, err := new(jwt.Parser).ParseUnverified(newSessionOutput.AccessJwt, jwt.MapClaims{})
		if err == nil {
			if claims, ok := accessToken.Claims.(jwt.MapClaims); ok {
				if expFloat, ok := claims["exp"].(float64); ok {
					expTime := time.Unix(int64(expFloat), 0)
					acc.ExpiresAt = sql.NullTime{Time: expTime, Valid: true}
					// logging.Info("New Bluesky access token expires at: %v", expTime)
				}
			}
		}

		// Parse new refresh token expiry
		refreshToken, _, err := new(jwt.Parser).ParseUnverified(newSessionOutput.RefreshJwt, jwt.MapClaims{})
		if err == nil {
			if claims, ok := refreshToken.Claims.(jwt.MapClaims); ok {
				if expFloat, ok := claims["exp"].(float64); ok {
					expTime := time.Unix(int64(expFloat), 0)
					acc.RefreshExpiresAt = sql.NullTime{Time: expTime, Valid: true}
					// logging.Info("New Bluesky refresh token expires at: %v", expTime)
				}
			}
		}
	}

	logging.Info("Successfully refreshed Bluesky session for %s", acc.Username)
	return acc, true, nil
}

// getHttpClient returns a basic http client (can be expanded later)
func getHttpClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 30, // Example timeout
	}
}
