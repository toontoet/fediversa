package sync

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fediversa/internal/api"
	"fediversa/internal/config"
	"fediversa/internal/database"
	"fediversa/internal/logging"
	"fediversa/internal/models"
	"fediversa/internal/transform"

	appbsky "github.com/bluesky-social/indigo/api/bsky"
	"github.com/ipfs/go-cid"
	"github.com/mattn/go-mastodon"
	// "fediversa/internal/transform"
)

// Syncer handles the periodic synchronization between services.
type Syncer struct {
	Config         *config.Config
	DB             *database.DB
	MastodonClient *api.MastodonClient
	BlueskyClient  *api.BlueskyClient
	Transformer    *transform.Transformer

	ticker *time.Ticker
	done   chan bool
}

// NewSyncer creates a new Syncer instance.
func NewSyncer(cfg *config.Config, db *database.DB, mc *api.MastodonClient, bc *api.BlueskyClient) *Syncer {
	transformer := transform.NewTransformer(cfg)
	return &Syncer{
		Config:         cfg,
		DB:             db,
		MastodonClient: mc,
		BlueskyClient:  bc,
		Transformer:    transformer,
		done:           make(chan bool),
	}
}

// Start begins the periodic synchronization process.
func (s *Syncer) Start() {
	if s.Config.SyncInterval <= 0 {
		logging.Warn("Sync interval is zero or negative, syncer will not run.")
		return
	}
	logging.Info("Starting syncer with interval: %s", s.Config.SyncInterval)
	s.ticker = time.NewTicker(s.Config.SyncInterval)

	go func() {
		// Run the first sync immediately
		logging.Info("Running initial sync cycle...")
		s.runSyncCycle(context.Background()) // Use background context for scheduled runs

		for {
			select {
			case <-s.done:
				logging.Info("Syncer ticker stopped.")
				return
			case t := <-s.ticker.C:
				logging.Info("Syncer tick at %s, running sync cycle...", t)
				s.runSyncCycle(context.Background())
			}
		}
	}()
}

// Stop halts the synchronization process.
func (s *Syncer) Stop() {
	if s.ticker != nil {
		logging.Info("Stopping syncer...")
		s.ticker.Stop()
		s.done <- true
		close(s.done)
		logging.Info("Syncer stopped.")
	}
}

// runSyncCycle performs one round of synchronization checks.
func (s *Syncer) runSyncCycle(ctx context.Context) {
	logging.Info("Starting sync cycle.")

	// 1. Check if both accounts are linked and authenticated
	mastodonAcc, errMasto := s.DB.GetAccountByService("mastodon")
	blueskyAcc, errBsky := s.DB.GetAccountByService("bluesky")

	if errMasto != nil || errBsky != nil {
		logging.Error("Sync cycle: Error fetching accounts: Masto: %v, Bsky: %v", errMasto, errBsky)
		return
	}

	if mastodonAcc == nil || blueskyAcc == nil {
		logging.Info("Sync cycle: One or both accounts not linked. Skipping sync.")
		// Optionally check tokens/sessions here even if account exists
		return
	}

	// TODO: Ensure clients are authenticated (using stored tokens/session)
	// This might involve refreshing tokens if necessary
	// Need to implement GetAuthenticatedClient methods in api clients

	// 2. Sync Mastodon -> Bluesky
	logging.Info("Sync cycle: Checking Mastodon for new posts...")
	errMastoToBsky := s.syncServiceToTarget(ctx, "mastodon", "bluesky", mastodonAcc, blueskyAcc)
	if errMastoToBsky != nil {
		logging.Error("Sync cycle: Error syncing Mastodon to Bluesky: %v", errMastoToBsky)
	}

	// 3. Sync Bluesky -> Mastodon
	logging.Info("Sync cycle: Checking Bluesky for new posts...")
	errBskyToMasto := s.syncServiceToTarget(ctx, "bluesky", "mastodon", blueskyAcc, mastodonAcc)
	if errBskyToMasto != nil {
		logging.Error("Sync cycle: Error syncing Bluesky to Mastodon: %v", errBskyToMasto)
	}

	logging.Info("Sync cycle finished.")
}

// syncServiceToTarget fetches posts from source and syncs them to target.
func (s *Syncer) syncServiceToTarget(ctx context.Context, sourceService, targetService string, sourceAcc, targetAcc *models.Account) error {
	logging.Info("Syncing from %s to %s", sourceService, targetService)
	var err error // Define error variable for the scope

	// --- Set Credentials/Session for Clients ---
	// Ensure the SOURCE client is ready to fetch
	if sourceService == "bluesky" {
		if err = s.BlueskyClient.SetSession(sourceAcc); err != nil {
			return fmt.Errorf("failed to set bluesky session for source account %s: %w", sourceAcc.Username, err)
		}
	} else if sourceService == "mastodon" {
		if !sourceAcc.AccessToken.Valid {
			return fmt.Errorf("mastodon source account %s is missing access token", sourceAcc.Username)
		}
		// Set the token for the Mastodon client instance used by the syncer
		s.MastodonClient.SetUserCredentials(sourceAcc.AccessToken.String)
		logging.Info("Set Mastodon credentials for source user %s", sourceAcc.Username)
	}

	// Ensure the TARGET client is ready to post
	if targetService == "bluesky" {
		// Check if session needs to be set/verified for posting
		if err = s.BlueskyClient.SetSession(targetAcc); err != nil {
			// Attempt re-authentication if setting session fails
			logging.Warn("Failed to set Bluesky session for target account %s, attempting re-auth: %v", targetAcc.Username, err)
			if targetAcc.AppPassword.Valid {
				newAcc, authErr := s.BlueskyClient.Authenticate(ctx, targetAcc.Username, targetAcc.AppPassword.String)
				if authErr != nil {
					return fmt.Errorf("bluesky re-authentication failed for target %s: %w", targetAcc.Username, authErr)
				}
				if saveErr := s.DB.SaveAccount(newAcc); saveErr != nil {
					logging.Error("Failed to save updated Bluesky account after re-authentication: %v", saveErr)
				}
			} else {
				return fmt.Errorf("cannot set bluesky session for target %s and no app password for re-auth", targetAcc.Username)
			}
		}
	} else if targetService == "mastodon" {
		if !targetAcc.AccessToken.Valid {
			return fmt.Errorf("mastodon target account %s is missing access token", targetAcc.Username)
		}
		// Set the token for the Mastodon client instance used by the syncer
		s.MastodonClient.SetUserCredentials(targetAcc.AccessToken.String)
		logging.Info("Set Mastodon credentials for target user %s", targetAcc.Username)
	}
	// --- End Set Credentials ---

	// 3. Get last checked post ID
	lastCheckedID, err := s.DB.GetLastCheckedPostID(sourceService)
	if err != nil {
		return fmt.Errorf("failed to get last checked post ID for %s: %w", sourceService, err)
	}

	isFirstSync := !lastCheckedID.Valid // Detect if this is the first sync
	var sinceID *string
	if !isFirstSync {
		sinceIDVal := lastCheckedID.String
		sinceID = &sinceIDVal
		logging.Info("Last checked post ID for %s: %s", sourceService, *sinceID)
	} else {
		logging.Info("First sync detected for %s. Fetching latest post to set baseline.", sourceService)
		// sinceID remains nil for the first fetch to get the latest post(s)
	}

	// 4. Fetch user's OWN posts from source using API wrapper methods
	var newPosts []interface{}
	var newestPostID string
	var fetchedStatuses []*mastodon.Status
	var fetchedFeed *appbsky.FeedGetAuthorFeed_Output

	switch sourceService {
	case "mastodon":
		// Use FetchAccountStatuses wrapper method
		pg := mastodon.Pagination{}
		if sinceID != nil {
			pg.SinceID = mastodon.ID(*sinceID)
		}
		// ExcludeReplies option is not available in this library version.
		// We filter replies client-side later in the loop.
		// if !s.Config.SyncReplies {
		// 	pg.ExcludeReplies = true
		// 	logging.Info("Excluding replies from Mastodon fetch.")
		// }
		logging.Info("Fetching Mastodon account statuses for user %s, since_id: %v", sourceAcc.UserID, pg.SinceID)
		fetchedStatuses, err = s.MastodonClient.FetchAccountStatuses(ctx, sourceAcc.UserID, &pg)
		if err != nil {
			return fmt.Errorf("failed to fetch Mastodon account statuses: %w", err)
		}
		if len(fetchedStatuses) > 0 {
			newestPostID = string(fetchedStatuses[0].ID)
			newPosts = make([]interface{}, len(fetchedStatuses))
			for i, status := range fetchedStatuses {
				newPosts[i] = status
			}
		}
	case "bluesky":
		// Use FetchAuthorFeed wrapper method
		var cursorVal string
		if sinceID != nil {
			logging.Warn("Bluesky GetAuthorFeed: sinceID present but cannot be used as cursor. Fetching latest.")
		}
		limit := int64(20) // TODO: Env var for limit?
		actorDID := sourceAcc.UserID
		logging.Info("Fetching Bluesky author feed for actor %s, cursor: '%s', limit: %d", actorDID, cursorVal, limit)

		fetchedFeed, err = s.BlueskyClient.FetchAuthorFeed(ctx, actorDID, cursorVal, limit)
		if err != nil {
			return fmt.Errorf("failed to fetch Bluesky author feed: %w", err)
		}
		if len(fetchedFeed.Feed) > 0 {
			if fetchedFeed.Feed[0].Post != nil {
				newestPostID = fetchedFeed.Feed[0].Post.Uri
			} else {
				logging.Warn("Newest post in Bluesky author feed has nil Post field.")
			}
			if fetchedFeed.Cursor != nil && *fetchedFeed.Cursor != "" {
				newestPostID = *fetchedFeed.Cursor
				logging.Info("Using Bluesky cursor as the newest marker: %s", newestPostID)
			} else {
				logging.Warn("Bluesky author feed fetch did not return a cursor. Using newest post URI as marker.")
			}
			newPosts = make([]interface{}, len(fetchedFeed.Feed))
			for i, postView := range fetchedFeed.Feed {
				newPosts[i] = postView
			}
		}
	default:
		return fmt.Errorf("unsupported source service: %s", sourceService)
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
		return nil
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
		return nil // Stop processing for this cycle after setting the baseline
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
		case *appbsky.FeedDefs_FeedViewPost:
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
			if feedPost, ok := p.Post.Record.Val.(*appbsky.FeedPost); ok {
				postContent = feedPost.Text
				// Extract media URLs/CIDs and alt texts from embed
				if feedPost.Embed != nil && feedPost.Embed.EmbedImages != nil {
					for _, img := range feedPost.Embed.EmbedImages.Images {
						if img.Image != nil && p.Post.Author != nil { // Check Author too
							// Store CID and DID to use SyncGetBlob later
							cidStr := img.Image.Ref.String()
							ownerDID := p.Post.Author.Did
							mediaIdentifier := fmt.Sprintf("did:%s/cid:%s", ownerDID, cidStr)
							originalMedia = append(originalMedia, mediaIdentifier)
							altTexts = append(altTexts, img.Alt)
						}
					}
				}
			} else {
				logging.Warn("Skipping Bluesky post %s: Record.Val is not *appbsky.FeedPost (%T)", sourcePostID, p.Post.Record.Val)
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

		// 8. Handle Media Attachments (Refactored)
		var targetMedia []*models.MediaAttachment                        // Slice to hold attachments for the target post
		mediaCtx, mediaCancel := context.WithTimeout(ctx, 2*time.Minute) // Timeout for all media ops for this post
		var mediaErr error                                               // Track errors during media processing

		if len(originalMedia) > 0 {
			logging.Info("Processing %d media attachments for post %s", len(originalMedia), sourcePostID)
			tempDirBase := filepath.Join(os.TempDir(), "fediversa-media")

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
				tempDir := filepath.Join(tempDirBase, sourcePostID, fmt.Sprintf("media_%d", idx))
				if strings.HasPrefix(mediaIdentifier, "did:") { // Bluesky Blob
					parts := strings.Split(strings.TrimPrefix(mediaIdentifier, "did:"), "/cid:")
					if len(parts) == 2 {
						ownerDID := parts[0]
						cidVal, err := cid.Decode(parts[1])
						if err != nil {
							downloadErr = fmt.Errorf("invalid CID %s: %w", parts[1], err)
						} else {
							downloadedFilePath, detectedContentType, cleanup, downloadErr = s.BlueskyClient.DownloadBlob(mediaCtx, ownerDID, cidVal, tempDir)
						}
					} else {
						downloadErr = fmt.Errorf("invalid bluesky media identifier: %s", mediaIdentifier)
					}
				} else { // Mastodon URL
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
						blb, err := s.BlueskyClient.UploadBlob(uploadCtx, attachment.Data, attachment.ContentType)
						if err != nil {
							uploadErr = fmt.Errorf("failed to upload blob to Bluesky: %w", err)
						} else {
							attachment.Blob = blb // Store the returned blob reference
							logging.Info("Uploaded blob to Bluesky for %s, CID: %s", attachment.URL, blb.Ref.String())
						}
					case "mastodon":
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

		// 9. Post to target service
		var targetPostID string
		var postErr error
		postCtx, postCancel := context.WithTimeout(ctx, 1*time.Minute)

		// Prepare reply info for target API
		var mastoReplyToID mastodon.ID
		var bskyReplyRef *appbsky.FeedPost_ReplyRef

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
					// Parse URI and create ref (ParseAtURI still needs to be created)
					parentRef, err := api.ParseAtURI(targetParentID)
					if err != nil {
						logging.Error("Failed to parse target parent URI %s for Bluesky reply: %v. Posting without threading.", targetParentID, err)
					} else {
						bskyReplyRef = &appbsky.FeedPost_ReplyRef{Root: parentRef, Parent: parentRef}
					}
				}
			} else {
				logging.Warn("Parent post %s for self-reply %s not found in sync DB for target %s. Posting without threading.", parentSourceID, sourcePostID, targetService)
			}
		}

		switch targetService {
		case "mastodon":
			targetPostID, postErr = s.MastodonClient.Post(postCtx, transformedContent, targetMedia, mastoReplyToID) // Pass reply ID
		case "bluesky":
			targetPostID, postErr = s.BlueskyClient.Post(postCtx, transformedContent, targetMedia, bskyReplyRef) // Pass reply ref
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
			TargetPostID:  targetPostID, // Use the ID returned by the Post method
		}
		if err := s.DB.SaveSyncedPost(syncedPost); err != nil {
			logging.Error("Failed to save sync record for source post %s: %v", sourcePostID, err)
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
	return nil
}

// Helper function to count posts regardless of type
func countPosts(posts interface{}) int {
	switch p := posts.(type) {
	case []*mastodon.Status:
		return len(p)
	case []*appbsky.FeedDefs_FeedViewPost:
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
