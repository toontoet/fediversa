package transform

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"fediversa/internal/config"
	"fediversa/internal/logging"

	"github.com/jaytaylor/html2text"
	"github.com/microcosm-cc/bluemonday"
)

// Transformer handles content transformations between services.
type Transformer struct {
	cfg           *config.Config
	htmlSanitizer *bluemonday.Policy
}

// NewTransformer creates a new Transformer instance.
func NewTransformer(cfg *config.Config) *Transformer {
	// Policy for stripping all HTML for plain text conversion
	p := bluemonday.StrictPolicy()
	// We will use html2text library for better conversion later,
	// but bluemonday can be a fallback or pre-processor.

	return &Transformer{
		cfg:           cfg,
		htmlSanitizer: p, // Keep strict policy for now
	}
}

// Transform applies necessary conversions to post content based on source and target services.
func (t *Transformer) Transform(content string, sourceService, targetService string) (string, error) {
	logging.Info("Transforming content from %s to %s", sourceService, targetService)
	transformedContent := content
	var err error

	switch {
	case sourceService == "mastodon" && targetService == "bluesky":
		// Mastodon -> Bluesky: Convert HTML to plain text, convert mentions
		transformedContent, err = t.htmlToPlainText(transformedContent)
		if err != nil {
			logging.Error("HTML to plain text conversion failed: %v. Using basic strip.", err)
			// Fallback to basic stripping maybe?
			transformedContent = t.basicStripHTML(content) // Use original content for stripping
		}
		transformedContent = t.convertMastodonMentionsToURL(transformedContent)
	case sourceService == "bluesky" && targetService == "mastodon":
		// Bluesky -> Mastodon: Convert mentions
		// Bluesky content is plain text with markdown-style links.
		// Mastodon handles plain text and auto-links URLs.
		transformedContent = t.convertBlueskyMentionsToURL(transformedContent)
	default:
		return "", fmt.Errorf("unsupported transformation: %s -> %s", sourceService, targetService)
	}

	// TODO: Add more transformations like hashtag conversion, link shortening/handling, etc.

	// logging.Debugf("Original content length: %d", len(content))
	// logging.Debugf("Transformed content length: %d", len(transformedContent))
	// Avoid logging full potentially long content at debug level unless necessary
	// logging.Debugf("Original content: %s", content)
	// logging.Debugf("Transformed content: %s", transformedContent)
	return transformedContent, nil
}

// htmlToPlainText converts HTML content to a cleaner plain text representation.
func (t *Transformer) htmlToPlainText(htmlContent string) (string, error) {
	// Options for html2text - experiment with these
	options := html2text.Options{
		PrettyTables: false, // Keep tables simple if they appear
		// OmitLinks: false, // Keep links
	}
	plainText, err := html2text.FromString(htmlContent, options)
	if err != nil {
		return "", fmt.Errorf("html2text conversion error: %w", err)
	}

	// html2text might leave some extra whitespace, clean it up.
	plainText = strings.TrimSpace(plainText)
	// Replace multiple newlines with a double newline (paragraph break)
	re := regexp.MustCompile(`\n{3,}`)
	plainText = re.ReplaceAllString(plainText, "\n\n")

	// Decode HTML entities that might remain
	plainText = html.UnescapeString(plainText)

	return plainText, nil
}

// basicStripHTML is a fallback stripper using bluemonday (less sophisticated than html2text).
func (t *Transformer) basicStripHTML(htmlContent string) string {
	sanitized := t.htmlSanitizer.Sanitize(htmlContent)
	decoded := html.UnescapeString(sanitized)
	return strings.TrimSpace(decoded)
}

// convertMastodonMentionsToURL converts @user@instance mentions to profile URLs.
func (t *Transformer) convertMastodonMentionsToURL(content string) string {
	// Regex to find mentions like @username@instance.domain
	// It captures the full mention, the username, and the instance.
	// (?i) makes it case-insensitive. (?:^|\s) ensures it's preceded by start or whitespace.
	re := regexp.MustCompile(`(?i)(?:^|\s)(@([a-zA-Z0-9_]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) >= 4 {
			mentionText := strings.TrimSpace(parts[0]) // The full mention like @user@host.com
			user := parts[2]
			instance := parts[3]
			profileURL := fmt.Sprintf("https://%s/@%s", instance, user)
			// For Bluesky, just append the URL in parentheses for now.
			// Bluesky doesn't auto-link mentions from other platforms well.
			// We keep the original mention text followed by the URL.
			return fmt.Sprintf("%s (%s)", mentionText, profileURL)
		}
		return match // Return original match if regex didn't capture parts correctly
	})
}

// convertBlueskyMentionsToURL converts @handle.domain mentions to profile URLs.
func (t *Transformer) convertBlueskyMentionsToURL(content string) string {
	// Regex to find mentions like @handle.tld or @handle.bsky.social
	// It captures the full mention and the handle.
	re := regexp.MustCompile(`(?i)(?:^|\s)(@([a-zA-Z0-9.-]+\.(?:bsky\.social|[a-zA-Z]{2,})))`)

	return re.ReplaceAllStringFunc(content, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) >= 3 {
			mentionText := strings.TrimSpace(parts[0]) // The full mention like @user.bsky.social
			handle := parts[2]
			profileURL := fmt.Sprintf("https://bsky.app/profile/%s", handle)
			// For Mastodon, appending the URL is usually sufficient as it auto-links.
			// We keep the original mention text followed by the URL.
			return fmt.Sprintf("%s (%s)", mentionText, profileURL)
		}
		return match // Return original match if regex didn't capture parts correctly
	})
}
