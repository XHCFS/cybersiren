package enricher

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// HTTPResult holds the HTTP fetch and HTML parse result.
type HTTPResult struct {
	StatusCode         int
	FinalURL           string
	Title              string
	Language           string
	FormActionDomain   string
	FaviconURL         string
	PasswordFieldCount int
	HasHiddenRedirect  bool
}

var (
	reTitleTag   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reLang       = regexp.MustCompile(`(?i)<html[^>]+lang=["']([^"']+)["']`)
	reFormAction = regexp.MustCompile(`(?i)<form[^>]+action=["']([^"'#?][^"']*)["']`)
	reFavicon    = regexp.MustCompile(`(?i)` +
		`<link[^>]+rel=["'][^"']*(?:shortcut\s+)?icon[^"']*["'][^>]+href=["']([^"']+)["']` +
		`|<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*(?:shortcut\s+)?icon[^"']*["']`)
	rePassword = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password["']?`)
	reHiddenRedirect = regexp.MustCompile(
		`(?i)<input[^>]+type\s*=\s*["']?hidden["']?[^>]+name\s*=\s*["']?` +
			`(?:redirect|return|return_to|next|goto|url|back|callback|destination)["']?`)

	httpClient = &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}
)

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

// FetchHTTP fetches rawURL and parses relevant fields from the HTML body.
// Returns zero-value HTTPResult (StatusCode=0) on error.
func FetchHTTP(ctx context.Context, rawURL string) HTTPResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HTTPResult{}
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := httpClient.Do(req)
	if err != nil {
		return HTTPResult{}
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// Read at most 512 KB to avoid memory issues on large pages.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return HTTPResult{StatusCode: resp.StatusCode, FinalURL: finalURL}
	}
	html := string(body)

	result := HTTPResult{
		StatusCode: resp.StatusCode,
		FinalURL:   finalURL,
	}

	if m := reTitleTag.FindStringSubmatch(html); len(m) > 1 {
		result.Title = strings.TrimSpace(stripTags(m[1]))
	}
	if m := reLang.FindStringSubmatch(html); len(m) > 1 {
		result.Language = strings.TrimSpace(m[1])
	}
	if m := reFormAction.FindStringSubmatch(html); len(m) > 1 {
		result.FormActionDomain = extractDomainFromHref(m[1], finalURL)
	}
	if m := reFavicon.FindStringSubmatch(html); len(m) > 0 {
		// Two capture groups (alternation); pick the non-empty one.
		for _, g := range m[1:] {
			if g != "" {
				result.FaviconURL = g
				break
			}
		}
	}
	result.PasswordFieldCount = len(rePassword.FindAllString(html, -1))
	result.HasHiddenRedirect = reHiddenRedirect.MatchString(html)

	return result
}

func stripTags(s string) string {
	reTag := regexp.MustCompile(`<[^>]+>`)
	return reTag.ReplaceAllString(s, "")
}

// extractDomainFromHref resolves href against base and returns its apex domain.
// Returns empty string for relative, fragment-only, or mailto: URLs.
func extractDomainFromHref(href, base string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		baseURL = &url.URL{}
	}
	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(parsed)
	if resolved.Host == "" {
		return ""
	}
	hostname := resolved.Hostname()
	apex, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		parts := strings.Split(hostname, ".")
		if len(parts) >= 2 {
			apex = strings.Join(parts[len(parts)-2:], ".")
		} else {
			apex = hostname
		}
	}
	return apex
}
