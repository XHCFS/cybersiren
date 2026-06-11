package notifier

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
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

// TestValkeyRateLimiterAllow_Live exercises the REAL ValkeyRateLimiter.Allow
// (the SET NX EX claim) against a live Valkey — the Handle-level tests all use
// the in-memory fakeLimiter, so this is the only coverage of the production
// limiter's behaviour and TTL. It is a DB/infra-integration test: it skips
// under -short and when VALKEY_ADDR is unset (CI sets VALKEY_ADDR=localhost:6379
// with infra up). Asserts the dedup contract — first Allow claims (true),
// second on the same key blocks (false) — and that the claim armed a TTL inside
// the (0, RateLimitTTLSeconds] window so a bucket can never be suppressed
// forever. A unique key per run avoids cross-run collisions.
func TestValkeyRateLimiterAllow_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Valkey-integration test under -short")
	}
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		t.Skip("set VALKEY_ADDR to run the live rate-limiter test")
	}

	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress:      []string{addr},
		ConnWriteTimeout: 3 * time.Second,
		Dialer:           net.Dialer{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("ping valkey: %v", err)
	}

	// Unique per run: test name + nanosecond + a fixed suffix.
	key := fmt.Sprintf("notif:test:%s:%d:f11", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		_ = client.Do(context.Background(), client.B().Del().Key(key).Build()).Error()
	})

	r := NewValkeyRateLimiter(client)

	allowed, err := r.Allow(ctx, key)
	if err != nil {
		t.Fatalf("first Allow error: %v", err)
	}
	if !allowed {
		t.Fatal("first Allow on a fresh key should claim the window (true)")
	}

	allowed, err = r.Allow(ctx, key)
	if err != nil {
		t.Fatalf("second Allow error: %v", err)
	}
	if allowed {
		t.Fatal("second Allow on the same key should be blocked (false)")
	}

	// The atomic SET NX EX must have armed a TTL within the configured window.
	ttl, err := client.Do(ctx, client.B().Ttl().Key(key).Build()).ToInt64()
	if err != nil {
		t.Fatalf("TTL lookup: %v", err)
	}
	if ttl <= 0 || ttl > RateLimitTTLSeconds {
		t.Errorf("TTL = %d, want within (0, %d]", ttl, RateLimitTTLSeconds)
	}
}
