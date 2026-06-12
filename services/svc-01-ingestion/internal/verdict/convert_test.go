package verdict

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestInt4Ptr(t *testing.T) {
	t.Parallel()
	if got := int4Ptr(false, 0); got != nil {
		t.Fatalf("invalid int4 should map to nil, got %v", *got)
	}
	// A real zero score must NOT collapse to null — 0 is a valid low-risk score.
	if got := int4Ptr(true, 0); got == nil || *got != 0 {
		t.Fatalf("valid 0 should map to *0, got %v", got)
	}
	if got := int4Ptr(true, 87); got == nil || *got != 87 {
		t.Fatalf("valid 87 should map to *87, got %v", got)
	}
}

func TestFloat8Ptr(t *testing.T) {
	t.Parallel()
	if got := float8Ptr(pgtype.Float8{}); got != nil {
		t.Fatalf("null confidence should map to nil, got %v", *got)
	}
	if got := float8Ptr(pgtype.Float8{Float64: 0.93, Valid: true}); got == nil || *got != 0.93 {
		t.Fatalf("valid confidence should map through, got %v", got)
	}
}

func TestTextOrEmpty(t *testing.T) {
	t.Parallel()
	if textOrEmpty(pgtype.Text{}) != "" {
		t.Fatal("null text should be empty string")
	}
	if textOrEmpty(pgtype.Text{String: "v2", Valid: true}) != "v2" {
		t.Fatal("valid text should pass through")
	}
}

func TestTsOrEmpty(t *testing.T) {
	t.Parallel()
	if tsOrEmpty(pgtype.Timestamptz{}) != "" {
		t.Fatal("null ts should be empty string")
	}
	when := time.Date(2026, 6, 12, 9, 30, 0, 0, time.UTC)
	if got := tsOrEmpty(pgtype.Timestamptz{Time: when, Valid: true}); got != "2026-06-12T09:30:00Z" {
		t.Fatalf("ts render mismatch: %q", got)
	}
}

func TestUUIDOrEmpty(t *testing.T) {
	t.Parallel()
	if uuidOrEmpty(pgtype.UUID{}) != "" {
		t.Fatal("null uuid should be empty string")
	}
	u := uuid.MustParse("018f3a2b-7c1d-7e2a-9b4c-0123456789ab")
	got := uuidOrEmpty(pgtype.UUID{Bytes: u, Valid: true})
	if got != u.String() {
		t.Fatalf("uuid render mismatch: got %q want %q", got, u.String())
	}
}
