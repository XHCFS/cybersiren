package store

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInt4ToInt(t *testing.T) {
	if got := int4ToInt(pgtype.Int4{}); got != 0 {
		t.Fatalf("invalid Int4 = %d, want 0", got)
	}
	if got := int4ToInt(pgtype.Int4{Int32: 73, Valid: true}); got != 73 {
		t.Fatalf("valid Int4 = %d, want 73", got)
	}
}

func TestNilIfEmpty(t *testing.T) {
	if nilIfEmpty(nil) != nil {
		t.Fatal("nil slice should stay nil")
	}
	if nilIfEmpty([]byte{}) != nil {
		t.Fatal("empty slice should become nil")
	}
	b := []byte(`{"a":1}`)
	if got := nilIfEmpty(b); !bytes.Equal(got, b) {
		t.Fatalf("non-empty slice should be returned verbatim, got %s", got)
	}
}

func TestNewRepoStore_NilPool(t *testing.T) {
	if NewRepoStore(nil) != nil {
		t.Fatal("NewRepoStore(nil) must return nil")
	}
}

// TestRepoStore_RoundTrip exercises the RepoStore against a live Postgres. It is
// a DB-integration test: it is skipped under `go test -short` (the unit gate)
// and additionally skips when APP_DATABASE_URL (the non-bypass app role DSN) is
// unset, so it only runs at the batch gate with infra up. It proves the four
// org-scoped writes round-trip through RLS.
func TestRepoStore_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test in -short mode")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for store integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	s := NewRepoStore(pool)
	const orgID = int64(1)
	sha := "0000000000000000000000000000000000000000000000000000000000000005"

	// A hash that was never observed must be a clean miss (no error).
	v, err := s.GetHashVerdict(ctx, orgID, sha+"ffff")
	if err != nil {
		t.Fatalf("hash miss errored: %v", err)
	}
	if v.Found {
		t.Fatal("unobserved hash should not be Found")
	}

	// Flag a malicious hash, then read it back.
	if err := s.FlagMalicious(ctx, orgID, sha, 90, []string{"malware"}); err != nil {
		t.Fatalf("flag malicious: %v", err)
	}
	got, err := s.GetHashVerdict(ctx, orgID, sha)
	if err != nil {
		t.Fatalf("read flagged hash: %v", err)
	}
	if !got.Found || !got.IsMalicious || got.RiskScore != 90 {
		t.Fatalf("flagged verdict mismatch: %+v", got)
	}

	// VT cache round-trip on the resolved library id.
	if err := s.CacheVT(ctx, orgID, got.ID, time.Now().UTC(), VTCacheInput{
		MaliciousVotes: 4,
		Raw:            []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":4}}}}`),
	}, time.Hour); err != nil {
		t.Fatalf("cache vt: %v", err)
	}
	cached, err := s.GetFreshVT(ctx, orgID, got.ID)
	if err != nil {
		t.Fatalf("read vt cache: %v", err)
	}
	if !cached.Found || cached.MaliciousVotes != 4 {
		t.Fatalf("vt cache mismatch: %+v", cached)
	}
}
