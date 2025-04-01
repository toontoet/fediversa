package sync

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/ipfs/go-cid"
	mastodon "github.com/mattn/go-mastodon"

	"fediversa/internal/api"
	"fediversa/internal/config"
	"fediversa/internal/database"
	"fediversa/internal/logging"
	"fediversa/internal/models"
	"fediversa/internal/transform"
)

// Syncer handles the overall synchronization process.
type Syncer struct {
	DB             *database.DB
	MastodonClient *api.MastodonClient
	BlueskyClient  *api.BlueskyClient
	Transformer    *transform.Transformer
	Config         *config.Config
	// IdentityCache  *identity.Cache // Removed - Type does not exist in current library version
}

// NewSyncer creates a new Syncer instance.
func NewSyncer(db *database.DB, mastodonClient *api.MastodonClient, blueskyClient *api.BlueskyClient, transformer *transform.Transformer, cfg *config.Config /*, idCache *identity.Cache */) *Syncer { // Removed idCache parameter
	return &Syncer{
		DB:             db,
		MastodonClient: mastodonClient,
		BlueskyClient:  blueskyClient,
		Transformer:    transformer,
		Config:         cfg,
		// IdentityCache:  idCache, // Removed
	}
}

// Run starts the synchronization loop.
func (s *Syncer) Run(ctx context.Context) {
	logging.Info("Starting initial sync cycle...")
	s.runSyncCycle(ctx)

	ticker := time.NewTicker(s.Config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logging.Info("Starting scheduled sync cycle...")
			s.runSyncCycle(ctx)
		case <-ctx.Done():
			logging.Info("Stopping syncer due to context cancellation.")
			return
		}
	}
}

// runSyncCycle performs one full sync cycle for all configured directions.
func (s *Syncer) runSyncCycle(ctx context.Context) {
	var wg sync.WaitGroup

	wg.Add(1)
	go s.syncServiceToTarget(ctx, "mastodon", "bluesky", &wg)

	wg.Add(1)
	go s.syncServiceToTarget(ctx, "bluesky", "mastodon", &wg)

	wg.Wait()
	logging.Info("Sync cycle finished.")
}

// syncServiceToTarget handles syncing posts from one service to another.
func (s *Syncer) syncServiceToTarget(ctx context.Context, sourceService, targetService string, wg *sync.WaitGroup) {
	defer wg.Done()

	logging.Info("Starting sync cycle: %s -> %s", sourceService, targetService)

	// 1. Get account details from DB
	sourceAcc, err := s.DB.GetAccountByService(sourceService)
	if err != nil {
		logging.Error("Sync cycle: Failed to get source account %s: %v", sourceService, err)
		return
	}
	if sourceAcc == nil {
		logging.Error("Sync cycle: Source account %s not found in database.", sourceService)
		return
	}

	targetAcc, err := s.DB.GetAccountByService(targetService)
	if err != nil {
		logging.Error("Sync cycle: Failed to get target account %s: %v", targetService, err)
		return
	}
	if targetAcc == nil {
		logging.Error("Sync cycle: Target account %s not found in database.", targetService)
		return
	}

	// --- 2. Set Credentials/Session for Clients (Original Structure) ---
	// --- Source Client Setup ---
	if sourceService == "bluesky" {
		// --> Refresh Bluesky source session if needed <--
		refreshed, err := s.refreshBlueskySessionIfNeededHelper(ctx, sourceAcc)
		if err != nil {
			// Log the specific error type (e.g., invalid refresh token vs other error)
			if strings.Contains(err.Error(), "invalid or expired refresh token") {
				logging.Error("Source Bluesky session refresh failed (token invalid/expired): %v. Manual re-login likely required.", err)
			} else {
				logging.Error("Failed to refresh source Bluesky session for %s: %v. Skipping sync.", sourceAcc.Username, err)
			}
			return // Stop this direction if refresh fails
		}
		if refreshed {
			if err := s.DB.SaveAccount(sourceAcc); err != nil {
				logging.Error("Failed to save refreshed source Bluesky account %s: %v", sourceAcc.Username, err)
				// Continue syncing even if save fails, but log the error
			}
		}
		// Always set the session after potential refresh
		if err = s.BlueskyClient.SetSession(sourceAcc); err != nil {
			// If setting session fails even after successful/no refresh, try re-auth
			logging.Warn("Failed to set Bluesky session for source %s after potential refresh, trying re-auth: %v", sourceAcc.Username, err)
			if sourceAcc.AppPassword.Valid {
				newAcc, authErr := s.BlueskyClient.Authenticate(ctx, sourceAcc.Username, sourceAcc.AppPassword.String)
				if authErr != nil {
					logging.Error("Bluesky re-authentication failed for source %s: %v", sourceAcc.Username, authErr)
					return // Stop if re-auth fails
				}
				if saveErr := s.DB.SaveAccount(newAcc); saveErr != nil {
					logging.Error("Failed to save updated Bluesky source account after re-authentication: %v", saveErr)
				}
				// Update sourceAcc with the newly authenticated details
				sourceAcc = newAcc
			} else {
				logging.Error("Cannot set Bluesky session for source %s and no app password for re-auth.", sourceAcc.Username)
				return // Stop if session cannot be set
			}
		}
		logging.Info("Set Bluesky session for source user %s", sourceAcc.Username)
	} else if sourceService == "mastodon" {
		if s.MastodonClient == nil {
			logging.Error("MastodonClient is nil for source %s", sourceService)
			return
		}
		if !sourceAcc.AccessToken.Valid {
			logging.Error("Mastodon source account %s is missing access token.", sourceAcc.Username)
			return
		}
		s.MastodonClient.SetUserCredentials(sourceAcc.AccessToken.String)
		logging.Info("Set Mastodon credentials for source user %s", sourceAcc.Username)
	}

	// --- Target Client Setup ---
	if targetService == "bluesky" {
		// --> Refresh Bluesky target session if needed <--
		refreshed, err := s.refreshBlueskySessionIfNeededHelper(ctx, targetAcc)
		if err != nil {
			// Log the specific error type
			if strings.Contains(err.Error(), "invalid or expired refresh token") {
				logging.Error("Target Bluesky session refresh failed (token invalid/expired): %v. Manual re-login likely required.", err)
			} else {
				logging.Error("Failed to refresh target Bluesky session for %s: %v. Skipping sync.", targetAcc.Username, err)
			}
			return // Stop this direction if refresh fails
		}
		if refreshed {
			if err := s.DB.SaveAccount(targetAcc); err != nil {
				logging.Error("Failed to save refreshed target Bluesky account %s: %v", targetAcc.Username, err)
				// Continue syncing even if save fails, but log the error
			}
		}
		// Always set the session after potential refresh
		if err = s.BlueskyClient.SetSession(targetAcc); err != nil {
			// If setting session fails even after successful/no refresh, try re-auth
			logging.Warn("Failed to set target Bluesky session for %s after potential refresh, attempting re-auth: %v", targetAcc.Username, err)
			if targetAcc.AppPassword.Valid {
				newAcc, authErr := s.BlueskyClient.Authenticate(ctx, targetAcc.Username, targetAcc.AppPassword.String)
				if authErr != nil {
					logging.Error("Bluesky re-authentication failed for target %s: %v", targetAcc.Username, authErr)
					return // Stop if re-auth fails
				}
				if saveErr := s.DB.SaveAccount(newAcc); saveErr != nil {
					logging.Error("Failed to save updated Bluesky target account after re-authentication: %v", saveErr)
				}
				// Update targetAcc with the newly authenticated details
				targetAcc = newAcc // Make sure to use the updated account info
			} else {
				logging.Error("Cannot set Bluesky session for target %s and no app password for re-auth.", targetAcc.Username)
				return // Stop if session cannot be set
			}
		}
		logging.Info("Set Bluesky session for target user %s", targetAcc.Username)
	} else if targetService == "mastodon" {
		if s.MastodonClient == nil {
			logging.Error("MastodonClient is nil for target %s", targetService)
			return
		}
		if !targetAcc.AccessToken.Valid {
			logging.Error("Mastodon target account %s is missing access token.", targetAcc.Username)
			return
		}
		s.MastodonClient.SetUserCredentials(targetAcc.AccessToken.String)
		logging.Info("Set Mastodon credentials for target user %s", targetAcc.Username)
	}

	// --- 3. Get last checked post ID ---
	lastCheckedID, err := s.DB.GetLastCheckedPostID(sourceService)
	if err != nil {
		logging.Error("Sync cycle: Failed to get last checked post ID for %s: %v", sourceService, err)
		return
	}
	isFirstSync := !lastCheckedID.Valid // Correctly define isFirstSync
	var lastCheckedIDStr *string
	if !isFirstSync {
		val := lastCheckedID.String
		lastCheckedIDStr = &val
		logging.Info("Last checked post ID for %s: %s", sourceService, *lastCheckedIDStr)
	} else {
		logging.Info("First sync detected for %s. Fetching latest post to set baseline.", sourceService)
	}

	// --- 4. Fetch posts from source ---
	var newPosts []interface{}
	var newestPostID string // Track the ID of the newest post fetched in this cycle

	switch sourceService {
	case "mastodon":
		pg := mastodon.Pagination{}
		if lastCheckedIDStr != nil {
			pg.SinceID = mastodon.ID(*lastCheckedIDStr)
		}
		logging.Info("Fetching Mastodon account statuses for user %s, since_id: %v", sourceAcc.UserID, pg.SinceID)
		fetchedStatuses, fetchErr := s.MastodonClient.FetchAccountStatuses(ctx, sourceAcc.UserID, &pg)
		if fetchErr != nil {
			logging.Error("Sync cycle: Error fetching Mastodon statuses: %v", fetchErr)
			return
		}
		// Convert to []interface{}
		for _, status := range fetchedStatuses {
			newPosts = append(newPosts, status)
		}
		if len(fetchedStatuses) > 0 {
			newestPostID = string(fetchedStatuses[0].ID) // Mastodon returns newest first
		}

	case "bluesky":
		// Remove incorrect config access for limit
		// limit := int64(s.Config.Sync.FetchLimit)
		// Use a fixed limit for now, or define it elsewhere if needed
		limit := int64(20)
		var cursorVal string // Start with empty cursor for latest
		// TODO: Implement proper Bluesky cursor handling based on lastCheckedID (if it's a TID).
		logging.Info("Fetching Bluesky author feed for actor %s, limit: %d", sourceAcc.UserID, limit)
		feed, fetchErr := s.BlueskyClient.FetchAuthorFeed(ctx, sourceAcc.UserID, cursorVal, limit) // Correctly define feed
		if fetchErr != nil {
			if strings.Contains(fetchErr.Error(), "ExpiredToken") {
				// This should ideally be caught by refresh logic later
				logging.Warn("Bluesky token expired during fetch for %s. Refresh logic (to be added) should handle this.", sourceAcc.Username)
				return // Stop this sync direction
			}
			logging.Error("Sync cycle: Error fetching Bluesky feed: %v", fetchErr)
			return
		}

		// --- Client-Side Filtering for Bluesky based on lastCheckedID ---
		filteredFeed := []*bsky.FeedDefs_FeedViewPost{}
		if lastCheckedIDStr != nil && *lastCheckedIDStr != "" {
			logging.Info("Filtering fetched Bluesky posts newer than baseline: %s", *lastCheckedIDStr)
			lastTid, err := extractTIDFromAtURI(*lastCheckedIDStr)
			if err != nil {
				logging.Warn("Could not extract TID from lastCheckedID URI %s: %v. Processing all fetched posts.", *lastCheckedIDStr, err)
				filteredFeed = feed.Feed // Fallback: process all if baseline URI is invalid
			} else {
				for _, postView := range feed.Feed {
					if postView.Post == nil {
						continue // Skip posts with nil data
					}
					currentTid, err := extractTIDFromAtURI(postView.Post.Uri)
					if err != nil {
						logging.Warn("Could not extract TID from post URI %s: %v. Skipping post.", postView.Post.Uri, err)
						continue
					}
					// Only include posts strictly newer than the last checked TID
					if currentTid > lastTid {
						filteredFeed = append(filteredFeed, postView)
					}
				}
				logging.Info("Filtered Bluesky posts: %d remaining after checking baseline TID %s", len(filteredFeed), lastTid)
			}
		} else {
			// No baseline set (should only happen on very first fetch before baseline is set)
			filteredFeed = feed.Feed
		}

		// Convert filtered FeedViewPost to []interface{}
		newPosts = make([]interface{}, len(filteredFeed))
		for i, postView := range filteredFeed {
			newPosts[i] = postView
		}
		if len(filteredFeed) > 0 && filteredFeed[0].Post != nil {
			newestPostID = filteredFeed[0].Post.Uri // Use newest from the *filtered* list for potential baseline update
		} else if len(feed.Feed) > 0 && feed.Feed[0].Post != nil {
			// If filtering resulted in empty list, still use the absolute newest for first-sync baseline
			newestPostID = feed.Feed[0].Post.Uri
		}
	default:
		logging.Error("Unsupported source service: %s", sourceService)
		return // Or handle error appropriately
	}

	if len(newPosts) == 0 {
		if isFirstSync {
			logging.Info("No posts found during first sync for %s. Baseline not set yet.", sourceService)
		} else {
			// Only log if suppression is disabled
			if !s.Config.SuppressNoNewPostsLogs {
				logging.Info("No new posts found for %s since last check.", sourceService)
			}
		}
		return // Function expects no return value
	}

	// If it was the first sync, only update the database with the newest ID and skip processing this batch.
	if isFirstSync {
		if newestPostID != "" {
			logging.Info("Setting baseline for %s with newest post ID: %s. Posts before this will not be synced.", sourceService, newestPostID)
			if err := s.DB.UpdateLastCheckedPostID(sourceService, newestPostID); err != nil {
				logging.Error("Failed to update initial last checked post ID for %s to %s: %v", sourceService, newestPostID, err)
				// Don't return error, let next cycle retry fetching based on no baseline
			} else {
				logging.Info("Successfully set baseline for %s.", sourceService)
			}
		} else {
			// Should not happen if len(newPosts) > 0, but log just in case
			logging.Warn("Fetched posts during first sync for %s, but could not determine newestPostID.", sourceService)
		}
		return // Function expects no return value
	}

	// --- If not the first sync, proceed to process fetched posts ---
	logging.Info("Fetched %d new posts from %s to process. Newest ID fetched: %s", len(newPosts), sourceService, newestPostID)

	// 5. Process posts in reverse order (oldest first) to maintain causality
	for i := len(newPosts) - 1; i >= 0; i-- {
		post := newPosts[i]
		var sourcePostID, postContent string
		var originalMedia []string    // URLs or Identifiers of media from the source post
		var altTexts []string         // Corresponding alt texts
		var isBoost bool              // Flag to indicate if the source was a boost
		var originalPostURL string    // URL of the original boosted post
		var isReply bool              // Flag if it's a reply
		var parentSourceID string     // ID/URI of the parent post
		var parentAuthorHandle string // Handle/Acct of the parent author
		var isSelfReply bool          // Flag if it's a reply to own post

		switch p := post.(type) {
		case *mastodon.Status:
			if p.Reblog != nil { // Boost
				isBoost = true
				if !s.Config.SyncBoostsReposts {
					logging.Info("Skipping Mastodon boost %s because SyncBoostsReposts is disabled.", p.ID)
					continue
				}
				logging.Info("Processing Mastodon boost ID: %s (Original: %s)", p.ID, p.Reblog.ID)
				sourcePostID = string(p.ID)    // Use the boost ID for tracking
				postContent = p.Reblog.Content // Content of the original post
				originalPostURL = p.Reblog.URL // URL of the original post
				// Extract media from the original post
				if len(p.Reblog.MediaAttachments) > 0 {
					for _, ma := range p.Reblog.MediaAttachments {
						originalMedia = append(originalMedia, ma.URL)
						altTexts = append(altTexts, ma.Description)
					}
				}
			} else { // Original post or reply
				if p.InReplyToID != nil {
					isReply = true
					// Apply explicit type assertion, but assert to string as indicated by runtime panic
					parentSourceID = p.InReplyToID.(string)
					parentAuthorHandle = p.InReplyToAccountID.(string)
					// Check if it's a reply to self
					// Use type assertion here too, comparing string ID to string ID
					if string(p.Account.ID) == p.InReplyToAccountID.(string) {
						isSelfReply = true
						logging.Info("Detected Mastodon reply to self: %s -> %s", p.ID, parentSourceID)
					} else {
						logging.Info("Detected Mastodon reply to other user (%s): %s -> %s", parentAuthorHandle, p.ID, parentSourceID)
					}
					// Filter based on config AFTER identifying details
					if !s.Config.SyncReplies {
						logging.Info("Skipping Mastodon reply %s because SyncReplies is disabled.", p.ID)
						continue
					}
				} else {
					isReply = false
				}
				isBoost = false
				sourcePostID = string(p.ID)
				postContent = p.Content
				// Extract media from this post
				if len(p.MediaAttachments) > 0 {
					for _, ma := range p.MediaAttachments {
						originalMedia = append(originalMedia, ma.URL)
						altTexts = append(altTexts, ma.Description)
					}
				}
			}
		case *bsky.FeedDefs_FeedViewPost:
			// Check for repost using the correct field - CURRENTLY SKIPPING ALL REPOSTS
			if p.Reason != nil && p.Reason.FeedDefs_ReasonRepost != nil {
				if p.Post != nil {
					logging.Info("Skipping Bluesky repost of URI: %s", p.Post.Uri)
				} else {
					logging.Info("Skipping Bluesky repost (original post data missing).")
				}
				continue
			}
			// Check for reply before general filtering
			if p.Reply != nil && p.Reply.Parent != nil {
				isReply = true

				// Check the nested structure identified via debug logs
				if p.Reply.Parent.FeedDefs_PostView != nil {
					parentSourceID = p.Reply.Parent.FeedDefs_PostView.Uri
					logging.Info("Successfully extracted parent URI from FeedDefs_PostView: %s", parentSourceID)
					// Attempt to get parent author handle from this structure too
					if p.Reply.Parent.FeedDefs_PostView.Author != nil {
						parentAuthorHandle = p.Reply.Parent.FeedDefs_PostView.Author.Handle
					} else {
						parentAuthorHandle = "[parent-author-unknown]"
						logging.Warn("Parent FeedDefs_PostView exists but Author field is nil for URI %s", parentSourceID)
					}
				} else {
					logging.Error("Bluesky reply parent does not contain FeedDefs_PostView (type: %T). Parent might be deleted or blocked. Cannot get parent URI.", p.Reply.Parent)
					continue // Skip processing this reply if parent info is unavailable
				}

				// Check if it's a reply to self
				if p.Post != nil && p.Post.Author != nil && p.Reply.Parent.FeedDefs_PostView != nil && p.Reply.Parent.FeedDefs_PostView.Author != nil {
					if p.Post.Author.Did == p.Reply.Parent.FeedDefs_PostView.Author.Did {
						isSelfReply = true
						logging.Info("Detected Bluesky reply to self: %s -> %s", p.Post.Uri, parentSourceID)
					} else {
						isSelfReply = false
						logging.Info("Detected Bluesky reply to other user (@%s): %s -> %s", parentAuthorHandle, p.Post.Uri, parentSourceID)
					}
				} else {
					isSelfReply = false // Cannot determine if author info is missing
					logging.Warn("Could not determine if Bluesky reply %s is self-reply due to missing author info.", p.Post.Uri)
				}

				// Filter based on config AFTER identifying details
				if !s.Config.SyncReplies {
					if p.Post != nil {
						logging.Info("Skipping Bluesky reply %s because SyncReplies is disabled.", p.Post.Uri)
					} else {
						logging.Info("Skipping Bluesky reply (post data missing) because SyncReplies is disabled.")
					}
					continue
				}
			} else {
				isReply = false
			}
			// Process as original post or non-filtered reply
			if p.Post == nil {
				logging.Warn("Skipping Bluesky FeedViewPost with nil Post field.")
				continue
			}
			sourcePostID = p.Post.Uri
			// Access post content via p.Post.Record, checking the type
			if p.Post.Record == nil {
				logging.Warn("Skipping Bluesky post %s: Record field is nil.", sourcePostID)
				continue
			}
			if feedPost, ok := p.Post.Record.Val.(*bsky.FeedPost); ok {
				postContent = feedPost.Text
				// Extract media URLs/CIDs and alt texts from embed
				if feedPost.Embed != nil && feedPost.Embed.EmbedImages != nil {
					for _, img := range feedPost.Embed.EmbedImages.Images {
						if img.Image != nil && p.Post.Author != nil { // Check Author too
							cidStr := img.Image.Ref.String()
							ownerDID := p.Post.Author.Did
							mediaIdentifier := fmt.Sprintf("did:%s/cid:%s", ownerDID, cidStr)
							originalMedia = append(originalMedia, mediaIdentifier)
							altTexts = append(altTexts, img.Alt)
						}
					}
				}
			} else {
				logging.Warn("Skipping Bluesky post %s: Record.Val is not *bsky.FeedPost (%T)", sourcePostID, p.Post.Record.Val)
				continue
			}
		default:
			logging.Warn("Skipping post of unknown type: %T", post)
			continue
		}

		// --- Echo Prevention Check ---
		isFromSync, err := s.DB.CheckIfPostIsFromSync(sourceService, sourcePostID)
		if err != nil {
			logging.Error("Failed to check echo status for %s post %s: %v. Skipping.", sourceService, sourcePostID, err)
			continue
		}
		if isFromSync {
			logging.Info("Skipping post %s from %s as it was originally synced from another service.", sourcePostID, sourceService)
			continue
		}
		// --- End Echo Prevention Check ---

		// 6. Check if post was already synced
		isSynced, err := s.DB.IsPostSynced(sourceService, sourcePostID, targetService)
		if err != nil {
			logging.Error("Failed to check sync status for %s post %s: %v. Skipping.", sourceService, sourcePostID, err)
			continue
		}
		if isSynced {
			logging.Info("Post %s from %s already synced to %s. Skipping.", sourcePostID, sourceService, targetService)
			continue
		}

		// 7. Transform content
		transformedContent, err := s.Transformer.Transform(postContent, sourceService, targetService)
		if err != nil {
			logging.Error("Failed to transform content for %s post %s: %v. Skipping.", sourceService, sourcePostID, err)
			continue
		}

		// Apply formatting for boosts or non-self-replies
		if isBoost {
			transformedContent = formatBoostText(transformedContent, originalPostURL)
		} else if isReply && !isSelfReply {
			transformedContent = formatReplyText(transformedContent, parentAuthorHandle)
		}

		// 8. Handle Media Attachments (Use direct clients)
		var targetMedia []*models.MediaAttachment                        // Slice to hold attachments for the target post
		mediaCtx, mediaCancel := context.WithTimeout(ctx, 2*time.Minute) // Declare mediaCtx
		var mediaErr error                                               // Track errors during media processing

		if len(originalMedia) > 0 {
			logging.Info("Processing %d media attachments for post %s", len(originalMedia), sourcePostID)
			tempDirBase := filepath.Join(os.TempDir(), "fediversa-media") // Declare tempDirBase

			for idx, mediaIdentifier := range originalMedia {
				altText := "" // Default alt text
				if idx < len(altTexts) {
					altText = altTexts[idx]
				}

				var downloadedFilePath string
				var detectedContentType string // Renamed from downloadedContentType
				var cleanup func()
				var downloadErr error
				var mediaData []byte

				// --- Download Phase ---
				tempDir := filepath.Join(tempDirBase, sourcePostID, fmt.Sprintf("media_%d", idx)) // Use tempDirBase
				if strings.HasPrefix(mediaIdentifier, "did:") {                                   // Bluesky Blob
					parts := strings.Split(strings.TrimPrefix(mediaIdentifier, "did:"), "/cid:")
					if len(parts) == 2 {
						ownerDID := parts[0]                // Use ownerDID
						cidVal, err := cid.Decode(parts[1]) // Use cidVal
						if err != nil {
							downloadErr = fmt.Errorf("invalid CID %s: %w", parts[1], err)
						} else {
							// Use direct client s.BlueskyClient
							downloadedFilePath, detectedContentType, cleanup, downloadErr = s.BlueskyClient.DownloadBlob(mediaCtx, ownerDID, cidVal, tempDir)
						}
					} else {
						downloadErr = fmt.Errorf("invalid bluesky media identifier: %s", mediaIdentifier)
					}
				} else { // Mastodon URL
					// Use direct client s.MastodonClient
					downloadedFilePath, cleanup, downloadErr = s.MastodonClient.DownloadMedia(mediaCtx, mediaIdentifier, tempDir)
				}

				if downloadErr != nil {
					logging.Error("Failed to download media %s: %v. Skipping attachment.", mediaIdentifier, downloadErr)
					if cleanup != nil {
						cleanup()
					}
					mediaErr = downloadErr // Record the first error encountered
					break                  // Stop processing media for this post if one fails
				}
				defer cleanup() // Schedule cleanup for this downloaded file

				// Read downloaded data
				mediaData, err = os.ReadFile(downloadedFilePath)
				if err != nil {
					logging.Error("Failed to read downloaded media file %s: %v. Skipping attachment.", downloadedFilePath, err)
					mediaErr = err
					break
				}

				// Detect content type if not already provided (e.g., from Bluesky download)
				if detectedContentType == "" {
					detectedContentType = http.DetectContentType(mediaData)
				}

				// Create initial MediaAttachment
				attachment := &models.MediaAttachment{
					URL:         mediaIdentifier,
					Data:        mediaData,
					ContentType: detectedContentType,
					Description: altText,
					Filename:    filepath.Base(downloadedFilePath),
				}
				targetMedia = append(targetMedia, attachment) // Add before upload attempt
			}
			mediaCancel() // Cancel context after downloads

			// --- Upload Phase (only if no download errors) ---
			if mediaErr == nil {
				logging.Info("Uploading %d media attachments to %s", len(targetMedia), targetService)
				uploadCtx, uploadCancel := context.WithTimeout(ctx, 2*time.Minute) // Separate timeout for uploads

				for _, attachment := range targetMedia {
					var uploadErr error
					switch targetService {
					case "bluesky":
						// Use direct client s.BlueskyClient
						blb, err := s.BlueskyClient.UploadBlob(uploadCtx, attachment.Data, attachment.ContentType)
						if err != nil {
							uploadErr = fmt.Errorf("failed to upload blob to Bluesky: %w", err)
						} else {
							attachment.Blob = blb // Store the returned blob reference
							logging.Info("Uploaded blob to Bluesky for %s, CID: %s", attachment.URL, blb.Ref.String())
						}
					case "mastodon":
						// Use direct client s.MastodonClient
						mastoAttach, err := s.MastodonClient.UploadBlob(uploadCtx, attachment.Data, attachment.ContentType, attachment.Filename)
						if err != nil {
							uploadErr = fmt.Errorf("failed to upload media to Mastodon: %w", err)
						} else {
							attachment.Attachment = mastoAttach // Store the returned attachment reference
							logging.Info("Uploaded media to Mastodon for %s, ID: %s", attachment.URL, mastoAttach.ID)
						}
					}

					if uploadErr != nil {
						logging.Error("Failed to upload media %s to %s: %v.", attachment.URL, targetService, uploadErr)
						mediaErr = uploadErr // Record first upload error
						break                // Stop uploading further media for this post
					}
				}
				uploadCancel()
			}
		}

		// If media processing failed, skip posting
		if mediaErr != nil {
			logging.Error("Skipping post %s/%s due to media processing error: %v", sourceService, sourcePostID, mediaErr)
			continue
		}

		// 9. Post to target service (Use direct clients)
		var targetPostID string
		var postErr error
		postCtx, postCancel := context.WithTimeout(ctx, 1*time.Minute)

		// Prepare reply info for target API
		var mastoReplyToID mastodon.ID
		var bskyReplyRef *bsky.FeedPost_ReplyRef // Use imported bsky type

		if isReply && isSelfReply {
			// Try to find the parent post on the target service
			targetParentID, found, dbErr := s.DB.GetTargetPostID(sourceService, parentSourceID, targetService)
			if dbErr != nil {
				logging.Error("Failed to query target parent ID for self-reply %s -> %s: %v. Posting without threading.", sourcePostID, parentSourceID, dbErr)
			} else if found {
				logging.Info("Found target parent ID %s for self-reply %s. Attempting to thread.", targetParentID, sourcePostID)
				if targetService == "mastodon" {
					mastoReplyToID = mastodon.ID(targetParentID)
				} else if targetService == "bluesky" {
					parentRef, err := api.ParseAtURI(targetParentID) // Ensure api.ParseAtURI exists and is correct
					if err != nil {
						logging.Error("Failed to parse target parent URI %s for Bluesky reply: %v. Posting without threading.", targetParentID, err)
					} else {
						bskyReplyRef = &bsky.FeedPost_ReplyRef{Root: parentRef, Parent: parentRef} // Use imported bsky type
					}
				}
			} else {
				logging.Warn("Parent post %s for self-reply %s not found in sync DB for target %s. Posting without threading.", parentSourceID, sourcePostID, targetService)
			}
		}

		switch targetService {
		case "mastodon":
			// Use direct client s.MastodonClient
			targetPostID, postErr = s.MastodonClient.Post(postCtx, transformedContent, targetMedia, mastoReplyToID)
		case "bluesky":
			// Use direct client s.BlueskyClient
			targetPostID, postErr = s.BlueskyClient.Post(postCtx, transformedContent, targetMedia, bskyReplyRef)
		default:
			postErr = fmt.Errorf("unsupported target service: %s", targetService)
		}
		postCancel()

		if postErr != nil {
			logging.Error("Failed to post to %s for source post %s: %v", targetService, sourcePostID, postErr)
			continue
		}

		logging.Info("Successfully posted source post %s to %s as post %s", sourcePostID, targetService, targetPostID)

		// 10. Record sync in DB
		syncedPost := &models.SyncedPost{
			SourceService: sourceService,
			SourcePostID:  sourcePostID,
			TargetService: targetService,
			TargetPostID:  targetPostID,
		}
		if err := s.DB.SaveSyncedPost(syncedPost); err != nil {
			// Log more prominently if saving the sync status fails, as this can cause duplicates
			logging.Error("CRITICAL: Failed to save sync record for source post %s -> target post %s. This may cause duplicates later! Error: %v", sourcePostID, targetPostID, err)
		}
	}

	// 11. Update last checked ID for the source service *after* processing all posts in a normal sync cycle
	// Use the newestPostID determined right after the fetch
	if !isFirstSync && newestPostID != "" { // Only update if it wasn't the first sync and we have a new ID
		if !lastCheckedID.Valid || newestPostID != lastCheckedID.String { // Avoid unnecessary DB write
			if err := s.DB.UpdateLastCheckedPostID(sourceService, newestPostID); err != nil {
				logging.Error("Failed to update last checked post ID for %s to %s: %v", sourceService, newestPostID, err)
			} else {
				logging.Info("Updated last checked post ID for %s to %s", sourceService, newestPostID)
			}
		}
	}

	logging.Info("Sync completed from %s to %s", sourceService, targetService)
}

// Helper function to count posts regardless of type
func countPosts(posts interface{}) int {
	switch p := posts.(type) {
	case []*mastodon.Status:
		return len(p)
	case []*bsky.FeedDefs_FeedViewPost:
		return len(p)
	default:
		return 0
	}
}

// basic HTML stripper (replace with a proper library like bluemonday later)
func stripHTML(input string) string {
	// This is very basic and might break things. Use with caution.
	output := input
	// Simple tags removal
	for _, tag := range []string{"<p>", "</p>", "<br>", "<br/>", "<br />"} {
		if tag == "<p>" || tag == "</p>" { // Replace paragraph tags with newlines
			output = strings.ReplaceAll(output, tag, "\n")
		} else if strings.HasPrefix(tag, "<br") { // Replace br tags with newlines
			output = strings.ReplaceAll(output, tag, "\n")
		}
	}
	// Remove remaining tags (very crude)
	for {
		start := strings.Index(output, "<")
		end := strings.Index(output, ">")
		if start == -1 || end == -1 || end < start {
			break
		}
		output = output[:start] + output[end+1:]
	}
	// Decode HTML entities (basic ones)
	output = strings.ReplaceAll(output, "&amp;", "&")
	output = strings.ReplaceAll(output, "&lt;", "<")
	output = strings.ReplaceAll(output, "&gt;", ">")
	output = strings.ReplaceAll(output, "&quot;", "\"")
	output = strings.ReplaceAll(output, "&apos;", "'")

	return strings.TrimSpace(output)
}

// formatBoostText adds a prefix indicating a boost and a link to the original.
func formatBoostText(originalContent, originalPostURL string) string {
	// Basic formatting, can be customized
	prefix := fmt.Sprintf("🔄 Boosted: %s\n\n", originalPostURL)
	return prefix + originalContent
}

// formatReplyText adds a prefix indicating a reply.
func formatReplyText(originalContent, parentAuthorHandle string) string {
	prefix := fmt.Sprintf("💬 Replying to @%s:\n\n", parentAuthorHandle)
	// Simple check for Mastodon ID (numeric) vs Bluesky handle
	if _, err := strconv.ParseInt(parentAuthorHandle, 10, 64); err == nil {
		prefix = fmt.Sprintf("💬 Replying to user ID %s:\n\n", parentAuthorHandle) // Avoid @ for numeric IDs
	}
	return prefix + originalContent
}

// TODO: Implement s.PostToTarget helper function later

// Helper function to call the exported RefreshSessionIfNeeded method
func (s *Syncer) refreshBlueskySessionIfNeededHelper(ctx context.Context, acc *models.Account) (bool, error) {
	if acc == nil || acc.Service != "bluesky" {
		return false, fmt.Errorf("invalid account provided for Bluesky session refresh")
	}
	if s.BlueskyClient == nil {
		return false, fmt.Errorf("bluesky client not initialized in syncer")
	}

	// Call the exported method
	_, refreshed, err := s.BlueskyClient.RefreshSessionIfNeeded(ctx, acc)
	if err != nil {
		return false, err // Propagate the error
	}
	return refreshed, nil
}

// extractTIDFromAtURI parses an at:// URI and returns the TID part.
func extractTIDFromAtURI(uri string) (string, error) {
	// Example URI: at://did:plc:lc5rl6rwa6mm42j4kr7xelbk/app.bsky.feed.post/3ljmbyu4zgr2o
	if !strings.HasPrefix(uri, "at://") {
		return "", fmt.Errorf("invalid AT URI format: does not start with at://")
	}
	parts := strings.Split(uri, "/")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid AT URI format: not enough parts")
	}
	// The TID is the last part
	tid := parts[len(parts)-1]
	if tid == "" {
		return "", fmt.Errorf("invalid AT URI format: empty TID part")
	}
	// Basic validation: TIDs are typically base32 Crockford encoded
	// For now, just check length and basic characters, could be more robust
	if len(tid) < 10 { // Arbitrary minimum length check
		// return "", fmt.Errorf("invalid TID format: too short")
		// Allow shorter for now, might be other URI types?
	}
	// Add more validation if needed
	return tid, nil
}
