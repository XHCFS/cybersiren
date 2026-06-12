package dedup

import (
	"context"
	"testing"
)

func TestClaim_EmptyMessageID_NeverDeduped(t *testing.T) {
	d := New(nil, nil)
	fresh, err := d.Claim(context.Background(), 1, "")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !fresh {
		t.Fatal("a message with no Message-ID must never be treated as a duplicate")
	}
}

func TestClaim_NoValkeyNoPool_FailsOpenAsFresh(t *testing.T) {
	// With neither Valkey nor a pool there is nothing to dedup against; rather
	// than drop a real email, Claim treats it as fresh and lets svc-02's
	// authoritative ON CONFLICT registration backstop any duplicate.
	d := New(nil, nil)
	fresh, err := d.Claim(context.Background(), 1, "m-1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !fresh {
		t.Fatal("no dedup backend available must fail open (fresh), not drop the email")
	}
}

func TestClaimKey_Format(t *testing.T) {
	if got := claimKey(7, "msg-abc"); got != "dedup:7:msg-abc" {
		t.Errorf("claimKey = %q, want dedup:7:msg-abc", got)
	}
}

func TestRelease_NoBackend_NoError(t *testing.T) {
	// Release is best-effort: with no Valkey client there is no claim key to drop,
	// so it must be a quiet no-op (never an error, never a panic) — the caller's
	// compensation path on the request hot path must not fail on it.
	d := New(nil, nil)
	if err := d.Release(context.Background(), 1, "m-1"); err != nil {
		t.Fatalf("Release with no Valkey must be a no-op, got %v", err)
	}
	if err := d.Release(context.Background(), 1, ""); err != nil {
		t.Fatalf("Release with an empty message id must be a no-op, got %v", err)
	}
}

func TestDBFallback_NilPool_FailsOpen(t *testing.T) {
	// The DB fallback fails OPEN per the package contract: with no pool it cannot
	// prove a duplicate, so it returns fresh=true (publish) rather than dropping
	// the email. The same fail-open posture applies to a DB read error, which
	// (requiring a live pool) is exercised in the dedup integration tests.
	d := New(nil, nil)
	fresh, err := d.dbFallback(context.Background(), 1, "m-1")
	if err != nil {
		t.Fatalf("dbFallback must not error when failing open, got %v", err)
	}
	if !fresh {
		t.Fatal("dbFallback must fail open (fresh=true), not drop the email")
	}
}
