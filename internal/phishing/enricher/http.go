package enricher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
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
	rePassword       = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password["']?`)
	reHiddenRedirect = regexp.MustCompile(
		`(?i)<input[^>]+type\s*=\s*["']?hidden["']?[^>]+name\s*=\s*["']?` +
			`(?:redirect|return|return_to|next|goto|url|back|callback|destination)["']?`)
	reStripTags = regexp.MustCompile(`<[^>]+>`)

	// errBlockedAddress is returned when the dialer resolves the target to a
	// private, loopback, link-local, or otherwise non-public address.
	errBlockedAddress = errors.New("blocked: non-public IP address")

	// httpFetchTimeout caps the whole fetch (connect + headers + the capped body
	// read). Lowered from 5s so the HTTP leg can't dominate the per-URL tail; the
	// enricher's overall cap is ~2s.
	httpClient = &http.Client{
		Timeout: 1500 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			// Re-validate the scheme of every redirect target. The dialer
			// already blocks non-public IPs at the TCP layer, but a redirect
			// to file:// / data:// / etc. would bypass DialContext entirely.
			if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return errBlockedAddress
			}
			return nil
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 1500 * time.Millisecond,
			DialContext:           safeDialContext,
		},
	}
)

// isPublicIPFn is the predicate the dialer uses to decide whether an
// IP address may be dialed. Tests can swap it (see http_test.go).
var isPublicIPFn = isPublicIP

// safeDialContext is an http.Transport DialContext that rejects targets
// resolving to non-public IPs (loopback, link-local incl. 169.254.169.254
// cloud metadata, private RFC1918/RFC4193, multicast, unspecified).
// Mitigates SSRF when fetching user-submitted URLs server-side.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host:port %q: %w", addr, err)
	}
	var resolver net.Resolver
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	var allowed []net.IP
	for _, ip := range ips {
		if isPublicIPFn(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, errBlockedAddress
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	var lastErr error
	for _, ip := range allowed {
		conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() {
		return false
	}
	return true
}

// blockNonPublicControl is a net.Dialer.Control hook that rejects a connection
// whose resolved destination is a non-public IP. It runs AFTER DNS resolution
// with the concrete ip:port, so unlike a pre-dial host check it also defeats
// DNS-rebinding. Use it on dialers that don't route through safeDialContext
// (e.g. the TLS dialer), so a user-submitted hostname cannot SSRF-probe an
// internal/cloud-metadata address.
func blockNonPublicControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host:port %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !isPublicIPFn(ip) {
		return errBlockedAddress
	}
	return nil
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

// httpBodyReadCap bounds how much of the response body FetchHTTP reads. The
// lightweight HTML signals we extract live in the <head> and early body, so
// 32 KB is enough while keeping the transfer (and thus the per-URL latency)
// bounded.
const httpBodyReadCap = 32 * 1024

// FetchHTTP fetches rawURL and parses relevant fields from the HTML body.
// Returns zero-value HTTPResult (StatusCode=0) on error, including refusal
// to fetch non-http(s) schemes and non-public IPs (SSRF guard).
func FetchHTTP(ctx context.Context, rawURL string) HTTPResult {
	ctx, span := enricherTracer.Start(ctx, "enricher.http.FetchHTTP")
	defer span.End()

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return HTTPResult{}
	}
	span.SetAttributes(attribute.String("enricher.host", parsed.Host), attribute.String("enricher.scheme", parsed.Scheme))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		span.RecordError(err)
		return HTTPResult{}
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return HTTPResult{}
	}
	defer resp.Body.Close()
	span.SetAttributes(attribute.Int("enricher.http_status", resp.StatusCode))

	finalURL := resp.Request.URL.String()

	// Read at most httpBodyReadCap. We keep a GET (not HEAD) so the lightweight
	// HTML signals we actually use — <title>, <html lang>, the first <form
	// action>, the favicon link, password-input and hidden-redirect markers —
	// are still extractable; those all live in the document <head> and early
	// body. Capping the read at 32 KB (down from 512 KB) bounds the transfer
	// time so a large or slow-streaming page can't blow the per-URL latency
	// budget, while still covering the head of essentially every real page.
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpBodyReadCap))
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
	return reStripTags.ReplaceAllString(s, "")
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
