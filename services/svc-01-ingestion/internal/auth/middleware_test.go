package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	sharedauth "github.com/saif/cybersiren/shared/auth"
)

// fakeKeys is an in-memory KeyReader keyed by lookup prefix. last_used_at is now
// touched on a detached goroutine, so touched is mutex-guarded to stay race-free.
type fakeKeys struct {
	rows   map[string][]APIKeyRow
	getErr error

	mu      sync.Mutex
	touched []int64
}

func (f *fakeKeys) GetAPIKeyByPrefix(_ context.Context, keyPrefix string) ([]APIKeyRow, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.rows[keyPrefix], nil
}

func (f *fakeKeys) TouchAPIKeyLastUsed(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
	return nil
}

// touchedIDs returns a snapshot of the keys touched so far.
func (f *fakeKeys) touchedIDs() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.touched...)
}

// waitForTouch polls up to a short deadline for the async last_used_at write to
// land. It returns the snapshot; a timeout returns whatever was seen.
func (f *fakeKeys) waitForTouch(t *testing.T) []int64 {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := f.touchedIDs(); len(got) > 0 {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	return f.touchedIDs()
}

// mint produces a valid key + its stored prefix/hash for org via the KeyManager.
func mint(t *testing.T, km *sharedauth.KeyManager) (plaintext, prefix, hash string) {
	t.Helper()
	g, err := km.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return g.Plaintext, g.Prefix, g.Hash
}

func newKM(t *testing.T) *sharedauth.KeyManager {
	t.Helper()
	km, err := sharedauth.NewKeyManager("cs_", 32, 4) // low bcrypt cost for fast tests
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	return km
}

// probe is the protected handler: it records the bound principal.
func probe(seen *Principal, hit *bool) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		*hit = true
		if p, ok := FromContext(r.Context()); ok {
			*seen = p
		}
	})
}

func TestMiddleware_ValidKey_BindsOrgFromKey(t *testing.T) {
	km := newKM(t)
	plaintext, prefix, hash := mint(t, km)
	keys := &fakeKeys{rows: map[string][]APIKeyRow{
		prefix: {{ID: 55, OrgID: 7, KeyHash: hash}},
	}}
	authn := NewAuthenticator(keys, km, zerolog.Nop())

	var seen Principal
	var hit bool
	h := authn.Middleware(probe(&seen, &hit))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !hit {
		t.Fatal("valid key must reach the protected handler")
	}
	if seen.OrgID != 7 || seen.APIKeyID != 55 {
		t.Errorf("principal = %+v, want org 7 / key 55", seen)
	}
	// last_used_at is now touched on a detached goroutine; the auth success above
	// is the load-bearing assertion. Wait briefly for the async write to confirm
	// it still targets the authenticating key.
	if touched := keys.waitForTouch(t); len(touched) != 1 || touched[0] != 55 {
		t.Errorf("last_used_at not touched for the authenticating key: %v", touched)
	}
}

func TestMiddleware_XAPIKeyHeader(t *testing.T) {
	km := newKM(t)
	plaintext, prefix, hash := mint(t, km)
	keys := &fakeKeys{rows: map[string][]APIKeyRow{prefix: {{ID: 1, OrgID: 3, KeyHash: hash}}}}
	authn := NewAuthenticator(keys, km, zerolog.Nop())

	var seen Principal
	var hit bool
	h := authn.Middleware(probe(&seen, &hit))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	req.Header.Set("X-API-Key", plaintext)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !hit || seen.OrgID != 3 {
		t.Fatalf("X-API-Key auth failed: hit=%v principal=%+v", hit, seen)
	}
}

func TestMiddleware_Rejections(t *testing.T) {
	km := newKM(t)
	plaintext, prefix, hash := mint(t, km)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name   string
		header string
		value  string
		rows   map[string][]APIKeyRow
	}{
		{"no header", "Authorization", "", nil},
		{"unknown prefix", "Authorization", "Bearer " + plaintext, map[string][]APIKeyRow{}},
		{"revoked", "Authorization", "Bearer " + plaintext, map[string][]APIKeyRow{prefix: {{ID: 1, OrgID: 7, KeyHash: hash, RevokedAt: &past}}}},
		{"expired", "Authorization", "Bearer " + plaintext, map[string][]APIKeyRow{prefix: {{ID: 1, OrgID: 7, KeyHash: hash, ExpiresAt: &past}}}},
		{"wrong key", "Authorization", "Bearer cs_thisisnottherealkey000000000000000000", map[string][]APIKeyRow{prefix: {{ID: 1, OrgID: 7, KeyHash: hash, ExpiresAt: &future}}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := &fakeKeys{rows: tc.rows}
			authn := NewAuthenticator(keys, km, zerolog.Nop())
			var hit bool
			var seen Principal
			h := authn.Middleware(probe(&seen, &hit))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
			if tc.value != "" {
				req.Header.Set(tc.header, tc.value)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if hit {
				t.Fatal("rejected request must NOT reach the protected handler")
			}
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
		})
	}
}
