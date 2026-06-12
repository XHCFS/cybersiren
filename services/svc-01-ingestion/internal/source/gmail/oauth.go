// Package gmail is svc-01's PRODUCTION Gmail EmailSource (ARCH-SPEC §2.1): an
// OAuth2-offline (refresh-token) Gmail API v1 client driven by a Google Pub/Sub
// PUSH webhook (POST /gmail/push) with a history.list fallback poll loop. Every
// fetched message is decoded to RFC-822 and handed to the SAME ingestion core as
// the API-upload adapter, so dedup/quota/UUIDv7 apply uniformly.
//
// Adapter scope (D2 / G2): API-upload + Gmail ONLY. IMAP and Outlook are
// deferred (P2) and MUST NOT be built here.
//
// The Gmail REST + OAuth calls are implemented on the standard library
// (net/http) on purpose: it keeps svc-01's dependency tree untouched and lets
// the recorded-fixture tests run fully offline against an httptest server (the
// only automated check the gate can run — there are no live Google creds in CI).
package gmail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// googleTokenURL is Google's OAuth2 token endpoint; overridable via config for
// tests.
const googleTokenURL = "https://oauth2.googleapis.com/token"

// tokenExpirySkew is subtracted from a token's lifetime so the adapter refreshes
// slightly before the real expiry, avoiding a race where a token expires
// mid-request.
const tokenExpirySkew = 60 * time.Second

// tokenSource mints short-lived access tokens from a long-lived offline refresh
// token (OAuth2 "refresh_token" grant). It caches the current access token and
// refreshes it on demand under a mutex, so concurrent callers (the push handler
// and the poll loop) share one token.
type tokenSource struct {
	clientID     string
	clientSecret string
	refreshToken string
	tokenURL     string
	httpClient   *http.Client

	mu      sync.Mutex
	access  string
	expires time.Time
}

// newTokenSource builds a tokenSource. tokenURL empty falls back to Google's.
func newTokenSource(clientID, clientSecret, refreshToken, tokenURL string, httpClient *http.Client) *tokenSource {
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &tokenSource{
		clientID:     clientID,
		clientSecret: clientSecret,
		refreshToken: refreshToken,
		tokenURL:     tokenURL,
		httpClient:   httpClient,
	}
}

// tokenResponse is the subset of the OAuth2 token endpoint reply we consume.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// token returns a valid access token, refreshing it from the refresh token when
// the cached one is empty or within tokenExpirySkew of expiry.
func (ts *tokenSource) token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.access != "" && time.Now().Before(ts.expires.Add(-tokenExpirySkew)) {
		return ts.access, nil
	}

	form := url.Values{
		"client_id":     {ts.clientID},
		"client_secret": {ts.clientSecret},
		"refresh_token": {ts.refreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		if tr.Error != "" {
			return "", fmt.Errorf("oauth token error (status %d): %s: %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
		}
		return "", fmt.Errorf("oauth token request failed: status %d", resp.StatusCode)
	}

	ts.access = tr.AccessToken
	// expires_in is seconds-from-now; default to a conservative 30m if absent.
	lifetime := time.Duration(tr.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	ts.expires = time.Now().Add(lifetime)
	return ts.access, nil
}
