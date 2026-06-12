package valkey

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
)

// liveClient dials the Valkey at VALKEY_ADDR, skipping the test cleanly under
// -short or when the env var is unset (no infra). It mirrors the gating used by
// the svc-09 store_test live test so `go test ./...` stays green without infra.
func liveClient(t *testing.T) valkeygo.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Valkey-integration test under -short")
	}
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		t.Skip("set VALKEY_ADDR to run the live valkey-primitive tests")
	}

	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress:      []string{addr},
		ConnWriteTimeout: 3 * time.Second,
		Dialer:           net.Dialer{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	t.Cleanup(client.Close)

	if err := client.Do(context.Background(), client.B().Ping().Build()).Error(); err != nil {
		t.Fatalf("ping valkey: %v", err)
	}
	return client
}

// uniqueKey returns a per-run key so concurrent/repeat runs never collide.
func uniqueKey(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("test:claim:%s:%d:%s", t.Name(), time.Now().UnixNano(), suffix)
}

// TestClaimRelease_Live exercises the atomic-claim primitive: the first Claim on
// a fresh key wins (true), a second blocks (false) with a TTL armed in the same
// command, and Release drops the key so a subsequent Claim wins again.
func TestClaimRelease_Live(t *testing.T) {
	client := liveClient(t)
	ctx := context.Background()
	key := uniqueKey(t, "cr")
	t.Cleanup(func() { _ = Release(context.Background(), client, key) })

	got, err := Claim(ctx, client, key, 3600)
	if err != nil {
		t.Fatalf("first Claim error: %v", err)
	}
	if !got {
		t.Fatal("first Claim on a fresh key must win (true)")
	}

	// The atomic SET NX EX must have armed a TTL within the requested window.
	ttl, err := client.Do(ctx, client.B().Ttl().Key(key).Build()).ToInt64()
	if err != nil {
		t.Fatalf("TTL lookup: %v", err)
	}
	if ttl <= 0 || ttl > 3600 {
		t.Errorf("TTL = %d, want within (0, 3600]", ttl)
	}

	got, err = Claim(ctx, client, key, 3600)
	if err != nil {
		t.Fatalf("second Claim error: %v", err)
	}
	if got {
		t.Fatal("second Claim on a held key must block (false)")
	}

	if err := Release(ctx, client, key); err != nil {
		t.Fatalf("Release error: %v", err)
	}

	got, err = Claim(ctx, client, key, 3600)
	if err != nil {
		t.Fatalf("Claim after Release error: %v", err)
	}
	if !got {
		t.Fatal("Claim after Release must win again (true)")
	}
}

// TestIncrWithExpiryDecr_Live exercises the windowed-counter primitive: INCR
// returns the running count, EXPIRE is armed only on the first write (count==1),
// and Decr backs the counter out.
func TestIncrWithExpiryDecr_Live(t *testing.T) {
	client := liveClient(t)
	ctx := context.Background()
	key := uniqueKey(t, "ctr")
	t.Cleanup(func() { _ = client.Do(context.Background(), client.B().Del().Key(key).Build()).Error() })

	n, err := IncrWithExpiry(ctx, client, key, 3600)
	if err != nil {
		t.Fatalf("first IncrWithExpiry error: %v", err)
	}
	if n != 1 {
		t.Fatalf("first count = %d, want 1", n)
	}

	// First write must have armed the TTL.
	ttl, err := client.Do(ctx, client.B().Ttl().Key(key).Build()).ToInt64()
	if err != nil {
		t.Fatalf("TTL lookup: %v", err)
	}
	if ttl <= 0 || ttl > 3600 {
		t.Errorf("TTL = %d, want within (0, 3600]", ttl)
	}

	n, err = IncrWithExpiry(ctx, client, key, 3600)
	if err != nil {
		t.Fatalf("second IncrWithExpiry error: %v", err)
	}
	if n != 2 {
		t.Fatalf("second count = %d, want 2", n)
	}

	if err := Decr(ctx, client, key); err != nil {
		t.Fatalf("Decr error: %v", err)
	}
	// GET returns the counter as a RESP3 blob string, so parse it with AsInt64
	// (string→int64); ToInt64 only accepts a RESP3 integer reply (as TTL/INCR
	// return) and would error "blob string is not a RESP3 int64".
	got, err := client.Do(ctx, client.B().Get().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("GET after Decr error: %v", err)
	}
	if got != 1 {
		t.Errorf("count after Decr = %d, want 1", got)
	}
}
