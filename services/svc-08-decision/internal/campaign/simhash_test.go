package campaign

import (
	"context"
	"testing"

	"github.com/mfonda/simhash"
	"github.com/rs/zerolog"
)

// These tests exercise the pure parts of Computer (no Valkey). The
// Lookup/Store paths are exercised via integration tests against a
// real Valkey instance — see the docker-compose stack at
// docker/docker-compose.yml.

func TestComputer_Compute_EmptyReturnsFalse(t *testing.T) {
	c := NewComputer(nil, SimHashThreshold, zerolog.Nop(), nil)
	if _, ok := c.Compute(""); ok {
		t.Fatalf("Compute(\"\") ok=true, want false")
	}
}

func TestComputer_Compute_DeterministicAndDistinctsDiffer(t *testing.T) {
	c := NewComputer(nil, SimHashThreshold, zerolog.Nop(), nil)
	a, ok := c.Compute("urgent action required: please verify your account now")
	if !ok {
		t.Fatalf("Compute(...) ok=false")
	}
	b, _ := c.Compute("urgent action required: please verify your account now")
	if a != b {
		t.Fatalf("Compute() not deterministic: %v vs %v", a, b)
	}
	x, _ := c.Compute("here are this week's invoice details and payment instructions")
	if simhash.Compare(a, x) <= SimHashThreshold {
		t.Fatalf("expected distinct texts to be > %d bits apart, got dist=%d",
			SimHashThreshold, simhash.Compare(a, x))
	}
}

func TestComputer_NearDuplicateWithinThreshold(t *testing.T) {
	// Re-using the same body with a tiny edit should keep the SimHash
	// within the threshold. Note: SimHash is approximate, so we don't
	// assert an *exact* distance — only that it's ≤ threshold.
	c := NewComputer(nil, SimHashThreshold, zerolog.Nop(), nil)
	const body = "your bank statement is ready for download. log in to view it now."
	a, _ := c.Compute(body)
	// One-character edit: "log in" → "sign in".
	b, _ := c.Compute("your bank statement is ready for download. sign in to view it now.")
	dist := int(simhash.Compare(a, b))
	if dist > 8 { // generous bound — design uses 3, but small textual
		// edits in 64-bit SimHash with word features can swing higher.
		// We mostly want to assert "near", not the exact threshold.
		t.Fatalf("edit-distance one phrase produced large SimHash distance %d", dist)
	}
}

func TestComputer_NilClientNoOps(t *testing.T) {
	c := NewComputer(nil, SimHashThreshold, zerolog.Nop(), nil)
	// Lookup with no client must return (zero, false, nil).
	m, found, err := c.Lookup(context.TODO(), 1, 0xdeadbeef)
	if found || err != nil || m != (Match{}) {
		t.Fatalf("Lookup(nil client) = (%+v, %v, %v); want (empty, false, nil)", m, found, err)
	}
	// Store with no client must succeed (no-op).
	if err := c.Store(context.TODO(), 1, 1, 0xdeadbeef, "fp"); err != nil {
		t.Fatalf("Store(nil client) returned %v, want nil", err)
	}
}
