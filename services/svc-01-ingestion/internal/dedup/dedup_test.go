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
