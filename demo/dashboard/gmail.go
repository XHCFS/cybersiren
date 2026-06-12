package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	gmailAPIBase   = "https://gmail.googleapis.com/gmail/v1/users/me"
	gmailScope     = "https://www.googleapis.com/auth/gmail.readonly openid email"
	// baselineForward caps how many recent inbox messages are scanned on the
	// first poll after connecting (so we give immediate feedback without bulk-
	// scanning the user's whole recent inbox); later polls scan all new arrivals.
	baselineForward = 3
)

// gmailConnector owns the interactive "Sign in with Google" flow and the
// background inbox poll loop. It holds the OAuth refresh token in memory (and
// optionally a local file), fetches new INBOX messages, and forwards each to
// svc-01's /api/v1/scan — exactly like a real user would, but driven from the
// throwaway demo rather than svc-01's own (spec) Gmail adapter.
type gmailConnector struct {
	cfg    config
	st     *store
	log    zerolog.Logger
	client *http.Client

	mu           sync.Mutex
	appCtx       context.Context
	connected    bool
	email        string
	refreshToken string
	states       map[string]time.Time
	seen         map[string]struct{}
	baselined    bool
	cancelPoll   context.CancelFunc
}

func newGmail(cfg config, st *store, log zerolog.Logger) *gmailConnector {
	return &gmailConnector{
		cfg: cfg, st: st, log: log,
		client: &http.Client{Timeout: 30 * time.Second},
		states: make(map[string]time.Time),
		seen:   make(map[string]struct{}),
	}
}

// resume stores the app context for poll loops and restarts polling if a token
// was persisted from a previous run.
func (g *gmailConnector) resume(ctx context.Context) {
	g.mu.Lock()
	g.appCtx = ctx
	g.mu.Unlock()
	if tok := g.loadToken(); tok != nil && tok.RefreshToken != "" {
		g.mu.Lock()
		g.connected = true
		g.email = tok.Email
		g.refreshToken = tok.RefreshToken
		g.mu.Unlock()
		g.startPoll()
		g.log.Info().Str("email", tok.Email).Msg("resumed Gmail connection from token file")
	}
}

func (g *gmailConnector) configured() bool {
	return g.cfg.GoogleClientID != "" && g.cfg.GoogleClientSecret != ""
}

func (g *gmailConnector) status() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]any{
		"configured": g.configured(),
		"connected":  g.connected,
		"email":      g.email,
		"mode":       "poll",
	}
}

func (g *gmailConnector) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !g.configured() {
		http.Error(w, "Gmail is not configured: set GOOGLE_CLIENT_ID/SECRET (see demo/dashboard/README.md)", http.StatusServiceUnavailable)
		return
	}
	state := randToken()
	g.mu.Lock()
	g.states[state] = time.Now()
	g.mu.Unlock()

	q := url.Values{}
	q.Set("client_id", g.cfg.GoogleClientID)
	q.Set("redirect_uri", g.cfg.GoogleRedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", gmailScope)
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	q.Set("include_granted_scopes", "true")
	q.Set("state", state)
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

func (g *gmailConnector) handleCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		http.Redirect(w, r, "/?gmail=error", http.StatusFound)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	g.mu.Lock()
	_, ok := g.states[state]
	delete(g.states, state)
	g.mu.Unlock()
	if !ok || code == "" {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}

	tr, err := g.exchangeCode(r.Context(), code)
	if err != nil {
		g.log.Error().Err(err).Msg("oauth code exchange failed")
		http.Redirect(w, r, "/?gmail=error", http.StatusFound)
		return
	}
	email := emailFromIDToken(tr.IDToken)

	g.mu.Lock()
	g.connected = true
	g.email = email
	g.refreshToken = tr.RefreshToken
	g.baselined = false
	g.seen = make(map[string]struct{})
	g.mu.Unlock()
	g.saveToken(&tokenFile{Email: email, RefreshToken: tr.RefreshToken})

	g.startPoll()
	http.Redirect(w, r, "/?gmail=connected", http.StatusFound)
}

func (g *gmailConnector) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.cancelPoll != nil {
		g.cancelPoll()
		g.cancelPoll = nil
	}
	g.connected = false
	g.email = ""
	g.refreshToken = ""
	g.mu.Unlock()
	if g.cfg.TokenFile != "" {
		_ = os.Remove(g.cfg.TokenFile)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

// startPoll launches (or restarts) the background inbox poll loop.
func (g *gmailConnector) startPoll() {
	g.mu.Lock()
	base := g.appCtx
	if g.cancelPoll != nil {
		g.cancelPoll()
	}
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	g.cancelPoll = cancel
	g.mu.Unlock()

	go func() {
		t := time.NewTicker(g.cfg.GmailPollInterval)
		defer t.Stop()
		g.pollOnce(ctx) // immediate first pass
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.pollOnce(ctx)
			}
		}
	}()
}

func (g *gmailConnector) pollOnce(ctx context.Context) {
	g.mu.Lock()
	refresh := g.refreshToken
	g.mu.Unlock()
	if refresh == "" {
		return
	}
	access, err := g.refreshAccess(ctx, refresh)
	if err != nil {
		g.log.Error().Err(err).Msg("gmail: token refresh failed")
		return
	}
	ids, err := g.listInbox(ctx, access)
	if err != nil {
		g.log.Error().Err(err).Msg("gmail: list inbox failed")
		return
	}

	g.mu.Lock()
	baselined := g.baselined
	g.baselined = true
	g.mu.Unlock()

	forwarded := 0
	for i, id := range ids {
		g.mu.Lock()
		_, dup := g.seen[id]
		g.seen[id] = struct{}{}
		g.mu.Unlock()
		if dup {
			continue
		}
		// On the first poll, only scan the few most-recent messages so we give
		// immediate feedback without bulk-scanning the whole recent inbox.
		if !baselined && i >= baselineForward {
			continue
		}
		raw, err := g.getRaw(ctx, access, id)
		if err != nil {
			g.log.Error().Err(err).Str("msg", id).Msg("gmail: fetch raw failed")
			continue
		}
		res, err := forwardToSvc01(ctx, g.client, g.cfg, raw)
		if err != nil {
			g.log.Error().Err(err).Msg("gmail: forward failed")
			continue
		}
		if res.EmailID != "" {
			subject, from := parseEmailMeta(raw)
			g.st.recordSubmit(res.EmailID, "gmail", subject, from)
			forwarded++
		}
	}
	if forwarded > 0 {
		g.log.Info().Int("count", forwarded).Msg("gmail: forwarded new messages to svc-01")
	}
}

// ── Google HTTP (hand-rolled; no Google SDK, matching the repo style) ────────

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Err          string `json:"error"`
	ErrDesc      string `json:"error_description"`
}

func (g *gmailConnector) tokenForm(ctx context.Context, form url.Values) (tokenResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResp{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client.Do(req)
	if err != nil {
		return tokenResp{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var tr tokenResp
	_ = json.Unmarshal(body, &tr)
	if tr.Err != "" {
		return tr, fmt.Errorf("google token error: %s: %s", tr.Err, tr.ErrDesc)
	}
	return tr, nil
}

func (g *gmailConnector) exchangeCode(ctx context.Context, code string) (tokenResp, error) {
	form := url.Values{
		"client_id":     {g.cfg.GoogleClientID},
		"client_secret": {g.cfg.GoogleClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {g.cfg.GoogleRedirectURL},
	}
	return g.tokenForm(ctx, form)
}

func (g *gmailConnector) refreshAccess(ctx context.Context, refresh string) (string, error) {
	form := url.Values{
		"client_id":     {g.cfg.GoogleClientID},
		"client_secret": {g.cfg.GoogleClientSecret},
		"refresh_token": {refresh},
		"grant_type":    {"refresh_token"},
	}
	tr, err := g.tokenForm(ctx, form)
	if err != nil {
		return "", err
	}
	return tr.AccessToken, nil
}

func (g *gmailConnector) listInbox(ctx context.Context, access string) ([]string, error) {
	u := gmailAPIBase + "/messages?labelIds=INBOX&q=" + url.QueryEscape("newer_than:1d") + "&maxResults=10"
	var out struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
	}
	if err := g.apiGet(ctx, access, u, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Messages))
	for _, m := range out.Messages {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

func (g *gmailConnector) getRaw(ctx context.Context, access, id string) ([]byte, error) {
	var out struct {
		Raw string `json:"raw"`
	}
	if err := g.apiGet(ctx, access, gmailAPIBase+"/messages/"+id+"?format=raw", &out); err != nil {
		return nil, err
	}
	return decodeWebSafeB64(out.Raw)
}

func (g *gmailConnector) apiGet(ctx context.Context, access, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gmail api %s: status %d", u, resp.StatusCode)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("gmail api %s: decode: %w", u, err)
	}
	return nil
}

// ── token persistence + helpers ──────────────────────────────────────────────

type tokenFile struct {
	Email        string `json:"email"`
	RefreshToken string `json:"refresh_token"`
}

func (g *gmailConnector) saveToken(t *tokenFile) {
	if g.cfg.TokenFile == "" {
		return
	}
	b, _ := json.Marshal(t)
	if err := os.WriteFile(g.cfg.TokenFile, b, 0o600); err != nil {
		g.log.Warn().Err(err).Msg("could not persist gmail token")
	}
}

func (g *gmailConnector) loadToken() *tokenFile {
	if g.cfg.TokenFile == "" {
		return nil
	}
	b, err := os.ReadFile(g.cfg.TokenFile)
	if err != nil {
		return nil
	}
	var t tokenFile
	if json.Unmarshal(b, &t) != nil {
		return nil
	}
	return &t
}

// emailFromIDToken extracts the "email" claim from a Google id_token JWT without
// verifying the signature (it came directly from Google's token endpoint over
// TLS, so it is trusted for display only).
func emailFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	_ = json.Unmarshal(payload, &claims)
	return claims.Email
}

func decodeWebSafeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode web-safe base64: %w", err)
	}
	return b, nil
}

func randToken() string {
	// Time-seeded, non-cryptographic state value — adequate CSRF nonce for a
	// localhost demo (the callback also validates it against the in-memory set).
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
