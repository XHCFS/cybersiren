package enricher

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// IsShortener returns true if rawURL's apex domain is in the known shortener list.
func IsShortener(rawURL string) bool {
	apex := apexFromURL(rawURL)
	if apex == "" {
		return false
	}
	_, ok := ShortenerApexes[apex]
	return ok
}

// ResolveShortURL follows redirects for known shortener URLs and returns
// the final destination URL. Returns empty string if:
//   - the URL is not from a known shortener
//   - resolution fails
//   - the final URL has the same apex as the input
func ResolveShortURL(ctx context.Context, rawURL string) (string, error) {
	if !IsShortener(rawURL) {
		return "", nil
	}

	ctx, span := enricherTracer.Start(ctx, "enricher.shortener.ResolveShortURL")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.short_url", rawURL))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// SSRF guard: rawURL is a shortener link from an incoming email and the
	// resolver follows its redirect chain. Route the dial through safeDialContext
	// (rejects non-public IPs, incl. 169.254.169.254 cloud metadata) and re-validate
	// every redirect target's scheme, mirroring the FetchHTTP client — otherwise an
	// attacker short link could redirect into an internal/metadata host.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return errBlockedAddress
			}
			return nil
		},
		Transport: &http.Transport{
			DialContext:           safeDialContext,
			ResponseHeaderTimeout: 5 * time.Second,
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", browserUA)

	resp, err := client.Do(req)
	if err != nil {
		// Fallback: try GET
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err2 != nil {
			return "", nil
		}
		req2.Header.Set("User-Agent", browserUA)
		resp, err = client.Do(req2)
		if err != nil {
			return "", nil
		}
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// Only return the resolved URL if it has a different apex domain.
	if apexFromURL(finalURL) == apexFromURL(rawURL) {
		return "", nil
	}
	return finalURL, nil
}

func apexFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
