package api_dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/saif/cybersiren/shared/auth"
	"github.com/saif/cybersiren/shared/config"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// TestRouterLoginAndRead DB-gates the end-to-end HTTP path: seed an org + user,
// log in for a JWT, then call a protected read endpoint. Skipped in -short/no-DB;
// runs in CI Integration.
func TestRouterLoginAndRead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test in -short mode")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config load failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DB.DSN())
	if err != nil {
		t.Skipf("no DB pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}

	uniq := time.Now().UnixNano()
	var orgID int64
	if err := pool.QueryRow(ctx, `INSERT INTO organisations (name, slug) VALUES ($1,$2) RETURNING id`,
		fmt.Sprintf("api-test-%d", uniq), fmt.Sprintf("api-test-%d", uniq)).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM organisations WHERE id=$1`, orgID) //nolint:errcheck

	email := fmt.Sprintf("admin-%d@x.test", uniq)
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (org_id, email, role, password_hash) VALUES ($1,$2,'admin'::user_role,$3)`,
		orgID, email, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	authCfg := config.AuthConfig{JWTSecret: "router-test-secret", JWTExpiry: time.Hour}
	authn := auth.New(nil, authCfg)
	recent := func() []contracts.EmailsVerdict { return nil }
	router := NewRouter(pool, nil, authn, recent, nil, zerolog.Nop())

	// Login → token.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "s3cret"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body %s, want 200", rr.Code, rr.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &loginResp); err != nil || loginResp.Token == "" {
		t.Fatalf("login response missing token: %v / %s", err, rr.Body.String())
	}

	// Wrong password → 401.
	bad, _ := json.Marshal(map[string]string{"email": email, "password": "nope"})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bad)))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("bad-password status = %d, want 401", rr.Code)
	}

	// Protected read with the token → 200.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats status = %d body %s, want 200", rr.Code, rr.Body.String())
	}

	// Protected read without a token → 401.
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no-token stats status = %d, want 401", rr.Code)
	}
}
