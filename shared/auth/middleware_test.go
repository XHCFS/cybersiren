package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
)

func okHandler(t *testing.T, wantOrg, wantUser int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := OrgIDFromContext(r.Context()); got != wantOrg {
			t.Errorf("org id = %d, want %d", got, wantOrg)
		}
		if got := UserIDFromContext(r.Context()); got != wantUser {
			t.Errorf("user id = %d, want %d", got, wantUser)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireAPIKey(t *testing.T) {
	t.Parallel()
	valid := dbsqlc.GetAPIKeyByHashRow{ID: 1, OrgID: 5, UserID: pgtype.Int8{Int64: 8, Valid: true}, Scopes: []string{"ingest"}}

	t.Run("valid key via X-API-Key sets context", func(t *testing.T) {
		t.Parallel()
		a := New(&fakeQuerier{row: valid}, testCfg())
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
		req.Header.Set("X-API-Key", "cs_key")
		a.RequireAPIKey(okHandler(t, 5, 8)).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("missing key → 401", func(t *testing.T) {
		t.Parallel()
		a := New(&fakeQuerier{row: valid}, testCfg())
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
		a.RequireAPIKey(okHandler(t, 0, 0)).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("revoked key → 401", func(t *testing.T) {
		t.Parallel()
		row := valid
		row.RevokedAt = pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}
		a := New(&fakeQuerier{row: row}, testCfg())
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
		req.Header.Set("Authorization", "Bearer cs_key")
		a.RequireAPIKey(okHandler(t, 0, 0)).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

func TestRequireJWT(t *testing.T) {
	t.Parallel()
	a := New(nil, testCfg())
	tok, _ := a.IssueJWT(11, 6, time.Hour)

	t.Run("valid token sets context", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		a.RequireJWT(okHandler(t, 6, 11)).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("garbage token → 401", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		req.Header.Set("Authorization", "Bearer not.a.jwt")
		a.RequireJWT(okHandler(t, 0, 0)).ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

func TestRequireScope(t *testing.T) {
	t.Parallel()
	a := New(nil, testCfg())
	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("has scope → 200", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		ctx := context.WithValue(context.Background(), ctxKeyScopes, []string{"ingest"})
		req := httptest.NewRequest(http.MethodPost, "/ingest", nil).WithContext(ctx)
		a.RequireScope("ingest")(final).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("missing scope → 403", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		ctx := context.WithValue(context.Background(), ctxKeyScopes, []string{"read"})
		req := httptest.NewRequest(http.MethodPost, "/ingest", nil).WithContext(ctx)
		a.RequireScope("ingest")(final).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
}
