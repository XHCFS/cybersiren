package quota

import (
	"context"
	"testing"
	"time"
)

func TestAllow_NilLimit_Unlimited(t *testing.T) {
	l := New(nil)
	ok, err := l.Allow(context.Background(), 1, nil)
	if err != nil || !ok {
		t.Fatalf("nil limit must be unlimited (allow), got ok=%v err=%v", ok, err)
	}
}

func TestAllow_ZeroLimit_Unlimited(t *testing.T) {
	l := New(nil)
	zero := int32(0)
	ok, err := l.Allow(context.Background(), 1, &zero)
	if err != nil || !ok {
		t.Fatalf("zero limit treated as unlimited, got ok=%v err=%v", ok, err)
	}
}

func TestAllow_NilValkey_FailsOpen(t *testing.T) {
	// A real limit but no Valkey client: the quota is a soft guard, so a missing
	// cache must fail open (allow) rather than wedge ingestion.
	l := New(nil)
	limit := int32(5)
	ok, err := l.Allow(context.Background(), 1, &limit)
	if err != nil || !ok {
		t.Fatalf("nil valkey must fail open (allow), got ok=%v err=%v", ok, err)
	}
}

func TestCounterKey_MonthScoped(t *testing.T) {
	now := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	if got := counterKey(42, now); got != "quota:42:202606" {
		t.Errorf("counterKey = %q, want quota:42:202606", got)
	}
}
