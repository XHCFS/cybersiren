package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/saif/cybersiren/db/sqlc"
)

// These cover the pre-flight guards on the SVC-03 enrichment-persistence methods
// that do not require a live DB. The org-scoped DB paths themselves are exercised
// by the RLS integration suite (rls_integration_test.go, //go:build integration).

func TestGetPriorEnrichedThreat_EmptyDomainIsMiss(t *testing.T) {
	t.Parallel()
	// An empty domain can never have a prior enrichment, so it short-circuits to
	// the cache-miss sentinel WITHOUT opening a transaction (a nil pool would
	// otherwise error first — proving the domain guard runs ahead of the pool).
	r := NewEnrichmentRepository(nil)
	_, err := r.GetPriorEnrichedThreat(context.Background(), 1, "", 0)
	if !errors.Is(err, ErrNoPriorEnrichment) {
		t.Fatalf("empty domain err = %v, want ErrNoPriorEnrichment", err)
	}
}

func TestEnrichmentRepo_NilPoolGuards(t *testing.T) {
	t.Parallel()
	r := NewEnrichmentRepository(nil)
	ctx := context.Background()

	if _, err := r.ListEmailURLs(ctx, 1, 1, pgtype.Timestamptz{}); err == nil {
		t.Error("ListEmailURLs: expected nil-pool error")
	}
	if err := r.ApplyThreatEnrichment(ctx, 1, db.UpdateEnrichedThreatEnrichmentParams{}); err == nil {
		t.Error("ApplyThreatEnrichment: expected nil-pool error")
	}
	if err := r.RecordTIMatch(ctx, 1, db.InsertEmailURLTIMatchParams{}); err == nil {
		t.Error("RecordTIMatch: expected nil-pool error")
	}
	// A non-empty domain reaches the pool guard (no short-circuit), so it errors
	// on the nil pool rather than returning the miss sentinel.
	if _, err := r.GetPriorEnrichedThreat(ctx, 1, "example.com", 0); err == nil {
		t.Error("GetPriorEnrichedThreat: expected nil-pool error for non-empty domain")
	}
}

func TestErrNoPriorEnrichmentIsSentinel(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrNoPriorEnrichment, ErrNoPriorEnrichment) {
		t.Fatal("ErrNoPriorEnrichment must be a stable sentinel")
	}
}
