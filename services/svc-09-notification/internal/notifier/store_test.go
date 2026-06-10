package notifier

import (
	"context"
	"testing"
)

func TestRateLimitKey(t *testing.T) {
	t.Parallel()
	camp := int64(99)
	if got := RateLimitKey(7, &camp, 123); got != "notif:7:99" {
		t.Errorf("with campaign: got %q, want notif:7:99", got)
	}
	if got := RateLimitKey(7, nil, 123); got != "notif:7:email-123" {
		t.Errorf("no campaign: got %q, want notif:7:email-123", got)
	}
}

func TestNilValkeyRateLimiterErrors(t *testing.T) {
	t.Parallel()
	r := NewValkeyRateLimiter(nil)
	if _, err := r.Allow(context.Background(), "notif:1:1"); err == nil {
		t.Fatal("expected error from nil-client limiter, got nil")
	}
}

// fakeLimiter is an in-memory RateLimiter: it allows the first Allow per key and
// blocks the rest, mirroring the INCR>1 block semantics without Redis.
type fakeLimiter struct {
	seen map[string]int
	err  error
}

func newFakeLimiter() *fakeLimiter { return &fakeLimiter{seen: map[string]int{}} }

func (f *fakeLimiter) Allow(_ context.Context, key string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.seen[key]++
	return f.seen[key] == 1, nil
}

func TestFakeLimiterAllowsOncePerKey(t *testing.T) {
	t.Parallel()
	f := newFakeLimiter()
	ctx := context.Background()
	if ok, _ := f.Allow(ctx, "k"); !ok {
		t.Fatal("first Allow should be true")
	}
	if ok, _ := f.Allow(ctx, "k"); ok {
		t.Fatal("second Allow on same key should be false")
	}
	if ok, _ := f.Allow(ctx, "other"); !ok {
		t.Fatal("first Allow on a different key should be true")
	}
}
