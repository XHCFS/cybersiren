package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	sharedauth "github.com/saif/cybersiren/shared/auth"

	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// fakeReader is an in-memory ConsoleReader for handler tests (no live DB).
type fakeReader struct {
	loginUser AuthUser
	loginErr  error
	gotOrgID  int64 // captured by the org-scoped methods to assert scoping
	emails    []EmailListItem
	emailsErr error
	detail    EmailDetail
	detailErr error
	rules     []RuleSummary
	ingestion IngestionStat
}

func (f *fakeReader) Login(_ context.Context, orgID int64, _, _ string) (AuthUser, error) {
	f.gotOrgID = orgID
	if f.loginErr != nil {
		return AuthUser{}, f.loginErr
	}
	return f.loginUser, nil
}

func (f *fakeReader) ListEmails(_ context.Context, orgID int64, _, _ int) ([]EmailListItem, error) {
	f.gotOrgID = orgID
	return f.emails, f.emailsErr
}

func (f *fakeReader) GetEmailDetail(_ context.Context, orgID int64, _ string) (EmailDetail, error) {
	f.gotOrgID = orgID
	return f.detail, f.detailErr
}

func (f *fakeReader) ListRules(_ context.Context, orgID int64) ([]RuleSummary, error) {
	f.gotOrgID = orgID
	return f.rules, nil
}
func (f *fakeReader) ThreatSummary(_ context.Context, orgID int64) ([]ThreatStat, error) {
	f.gotOrgID = orgID
	return nil, nil
}
func (f *fakeReader) CampaignSummary(_ context.Context, orgID int64) ([]CampaignStat, error) {
	f.gotOrgID = orgID
	return nil, nil
}
func (f *fakeReader) FeedHealth(_ context.Context, orgID int64) ([]FeedStat, error) {
	f.gotOrgID = orgID
	return nil, nil
}
func (f *fakeReader) RulePerformance(_ context.Context, orgID int64) ([]RuleStat, error) {
	f.gotOrgID = orgID
	return nil, nil
}
func (f *fakeReader) OrgIngestionSummary(_ context.Context, orgID int64) (IngestionStat, error) {
	f.gotOrgID = orgID
	return f.ingestion, nil
}

// stubIssuer mints a fixed token and records the identity it was asked to sign.
type stubIssuer struct {
	token    string
	err      error
	gotOrg   int64
	gotUser  int64
	gotEmail string
}

func (s *stubIssuer) Issue(userID, orgID int64, _ sharedauth.Role, email string) (string, error) {
	s.gotUser, s.gotOrg, s.gotEmail = userID, orgID, email
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func newTestAPI(reader ConsoleReader, issuer Issuer) *API {
	return &API{
		Reader: reader,
		Issuer: issuer,
		Log:    zerolog.Nop(),
		OrgID:  1,
	}
}

// ── login ────────────────────────────────────────────────────────────────────

func TestHandleLogin_Success(t *testing.T) {
	reader := &fakeReader{loginUser: AuthUser{
		ID: 7, Email: "analyst@demo.cybersiren", DisplayName: "Demo Analyst", Role: "analyst", OrgID: 1,
	}}
	issuer := &stubIssuer{token: "signed.jwt.token"}
	api := newTestAPI(reader, issuer)

	rr := doJSON(t, http.MethodPost, "/api/v1/auth/login",
		`{"email":"analyst@demo.cybersiren","password":"hunter2"}`, api.HandleLogin)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp loginResponse
	mustJSON(t, rr, &resp)
	if resp.Token != "signed.jwt.token" {
		t.Errorf("token = %q, want signed.jwt.token", resp.Token)
	}
	if resp.User.ID != 7 || resp.User.Role != "analyst" || resp.User.OrgID != 1 {
		t.Errorf("user = %+v, unexpected", resp.User)
	}
	// Login must resolve against the hardcoded MVP-1 org.
	if reader.gotOrgID != 1 {
		t.Errorf("login org = %d, want 1", reader.gotOrgID)
	}
	if issuer.gotUser != 7 || issuer.gotOrg != 1 {
		t.Errorf("issuer asked to sign user=%d org=%d, want 7/1", issuer.gotUser, issuer.gotOrg)
	}
}

func TestHandleLogin_Failures(t *testing.T) {
	// Every credential failure must be a generic 401 with NO field-specific leak.
	cases := []struct {
		name string
		body string
		err  error
	}{
		{"wrong password", `{"email":"a@b.c","password":"bad"}`, ErrInvalidCredentials},
		{"unknown user", `{"email":"nobody@b.c","password":"x"}`, ErrInvalidCredentials},
		{"null hash user", `{"email":"a@b.c","password":"x"}`, ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := &fakeReader{loginErr: tc.err}
			api := newTestAPI(reader, &stubIssuer{token: "should-not-be-issued"})
			rr := doJSON(t, http.MethodPost, "/api/v1/auth/login", tc.body, api.HandleLogin)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			var resp map[string]string
			mustJSON(t, rr, &resp)
			if resp["error"] != "invalid email or password" {
				t.Errorf("error = %q, want generic message", resp["error"])
			}
			// The generic message must not name a field.
			if strings.Contains(resp["error"], "user") || strings.Contains(resp["error"], "hash") {
				t.Errorf("error message leaks which field failed: %q", resp["error"])
			}
		})
	}
}

func TestHandleLogin_BadRequest(t *testing.T) {
	api := newTestAPI(&fakeReader{}, &stubIssuer{})
	for _, body := range []string{`{}`, `{"email":"a@b.c"}`, `not json`} {
		rr := doJSON(t, http.MethodPost, "/api/v1/auth/login", body, api.HandleLogin)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rr.Code)
		}
	}
}

// ── verifyPassword (bcrypt + NULL hash) ──────────────────────────────────────

func TestVerifyPassword(t *testing.T) {
	const plaintext = "correct horse battery staple"
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), 4) // low cost for test speed
	if err != nil {
		t.Fatal(err)
	}
	stored := pgtype.Text{String: string(hash), Valid: true}

	if err := verifyPassword(stored, plaintext); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := verifyPassword(stored, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v, want ErrInvalidCredentials", err)
	}
	// NULL hash (user has no local password) must always fail.
	if err := verifyPassword(pgtype.Text{Valid: false}, plaintext); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("NULL hash: err = %v, want ErrInvalidCredentials", err)
	}
	// Empty-string hash must also fail.
	if err := verifyPassword(pgtype.Text{String: "", Valid: true}, plaintext); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("empty hash: err = %v, want ErrInvalidCredentials", err)
	}
}

// ── read handler: org scoping + JSON shape + 404 ─────────────────────────────

func TestHandleListEmails_ScopingAndShape(t *testing.T) {
	rs := int32(82)
	reader := &fakeReader{emails: []EmailListItem{
		{EmailID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", InternalID: 42, Subject: "Reset your password", RiskScore: &rs, VerdictLabel: "phishing"},
	}}
	api := newTestAPI(reader, &stubIssuer{})

	// Build an authenticated request: claims carry org 9 (NOT the login org), to
	// prove the handler scopes by the JWT claim, not a constant.
	req := authedRequest(http.MethodGet, "/api/v1/emails?limit=10&offset=0", 9)
	rr := httptest.NewRecorder()
	api.HandleListEmails(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if reader.gotOrgID != 9 {
		t.Errorf("ListEmails scoped to org %d, want 9 (from JWT claim)", reader.gotOrgID)
	}
	var page Page[EmailListItem]
	mustJSON(t, rr, &page)
	if page.Count != 1 || len(page.Items) != 1 {
		t.Fatalf("page count = %d, want 1", page.Count)
	}
	if page.Items[0].VerdictLabel != "phishing" || *page.Items[0].RiskScore != 82 {
		t.Errorf("item shape unexpected: %+v", page.Items[0])
	}
	if page.Limit != 10 {
		t.Errorf("limit echo = %d, want 10", page.Limit)
	}
}

func TestHandleListEmails_EmptyIsArrayNotNull(t *testing.T) {
	api := newTestAPI(&fakeReader{emails: nil}, &stubIssuer{})
	req := authedRequest(http.MethodGet, "/api/v1/emails", 1)
	rr := httptest.NewRecorder()
	api.HandleListEmails(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// Items must serialise as [] not null.
	if !strings.Contains(rr.Body.String(), `"items":[]`) {
		t.Errorf("empty items not [] in body: %s", rr.Body.String())
	}
}

func TestHandleListEmails_BadPagination(t *testing.T) {
	api := newTestAPI(&fakeReader{}, &stubIssuer{})
	req := authedRequest(http.MethodGet, "/api/v1/emails?limit=-5", 1)
	rr := httptest.NewRecorder()
	api.HandleListEmails(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for negative limit", rr.Code)
	}
}

func TestHandleGetEmail_NotFound(t *testing.T) {
	reader := &fakeReader{detailErr: ErrNotFound}
	api := newTestAPI(reader, &stubIssuer{})

	// Route through a real mux so PathValue("id") is populated.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/emails/{id}", api.HandleGetEmail)
	req := authedRequest(http.MethodGet, "/api/v1/emails/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", 1)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if reader.gotOrgID != 1 {
		t.Errorf("detail scoped to org %d, want 1", reader.gotOrgID)
	}
}

func TestHandleGetEmail_Detail(t *testing.T) {
	reader := &fakeReader{detail: EmailDetail{
		EmailID:        "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
		InternalID:     42,
		Subject:        "Invoice",
		CurrentVerdict: &Verdict{Label: "benign", Source: "model"},
		VerdictHistory: []Verdict{{ID: 1, Label: "benign", Source: "model"}},
		RuleHits:       []RuleHit{},
		URLs:           []EmailURL{},
		Attachments:    []Attachment{},
		Recipients:     []Recipient{},
	}}
	api := newTestAPI(reader, &stubIssuer{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/emails/{id}", api.HandleGetEmail)
	req := authedRequest(http.MethodGet, "/api/v1/emails/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", 1)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got EmailDetail
	mustJSON(t, rr, &got)
	if got.InternalID != 42 || got.CurrentVerdict == nil || got.CurrentVerdict.Label != "benign" {
		t.Errorf("detail shape unexpected: %+v", got)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func doJSON(t *testing.T, method, path, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// authedRequest builds a request whose context carries verified claims for the
// given org, simulating a request that already passed the auth middleware.
func authedRequest(method, path string, orgID int64) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	claims := &sharedauth.Claims{UserID: 1, OrgID: orgID, Role: sharedauth.RoleAnalyst, Email: "a@b.c"}
	return req.WithContext(middleware.WithClaims(req.Context(), claims))
}

func mustJSON(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
}
