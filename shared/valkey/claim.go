package valkey

import (
	"context"

	valkeygo "github.com/valkey-io/valkey-go"
)

// claim.go holds the small atomic-claim and windowed-counter primitives shared
// across services (svc-01 dedup + quota, svc-09 notification rate-limit). Each
// function performs exactly ONE Valkey idiom and returns the raw op result; the
// caller owns all policy (fail-open vs fail-closed, error wrapping, nil-client
// guards, key construction). Errors are returned unwrapped so callers keep
// their existing, contract-tested error messages byte-for-byte.

// Claim performs an atomic SET key "1" NX EX ttl. It returns (true, nil) when
// the key was newly set (the first writer in the window) and (false, nil) when
// the key already existed (a duplicate — the NX no-op surfaces as a Valkey nil
// reply). Any other error is returned unwrapped with claimed=false, so the
// caller can apply its own degrade/fail-open policy. Because the claim and the
// TTL land in a single command, a crashed round-trip can never leave the key
// without an expiry.
func Claim(ctx context.Context, client valkeygo.Client, key string, ttlSeconds int64) (bool, error) {
	_, err := client.Do(ctx,
		client.B().Set().Key(key).Value("1").Nx().ExSeconds(ttlSeconds).Build(),
	).ToString()
	switch {
	case err == nil:
		return true, nil // claimed → new
	case valkeygo.IsValkeyNil(err):
		return false, nil // key already present → not claimed (duplicate)
	default:
		return false, err
	}
}

// Release drops the key with DEL. It is the compensation for a Claim that must
// be undone (e.g. a request that claimed but then failed downstream). The DEL
// error, if any, is returned unwrapped for the caller to log; callers treat
// Release as best-effort since the claim's TTL will evict the key regardless.
func Release(ctx context.Context, client valkeygo.Client, key string) error {
	return client.Do(ctx, client.B().Del().Key(key).Build()).Error()
}

// IncrWithExpiry performs INCR key and arms EXPIRE key ttl exactly once — only
// on the INCR that returns 1 (the key's first write in the window). This keeps
// the TTL set once and prevents a later EXPIRE from resetting a mid-window
// counter. It returns the post-increment count and any error unwrapped. On an
// INCR error the count is 0; on an EXPIRE error the (already-incremented) count
// is still returned so the caller can decide policy with full information.
func IncrWithExpiry(ctx context.Context, client valkeygo.Client, key string, ttlSeconds int64) (int64, error) {
	count, err := client.Do(ctx, client.B().Incr().Key(key).Build()).ToInt64()
	if err != nil {
		return count, err
	}
	if count == 1 {
		// First write this window: arm the TTL so the counter self-evicts.
		if expErr := client.Do(ctx,
			client.B().Expire().Key(key).Seconds(ttlSeconds).Build(),
		).Error(); expErr != nil {
			return count, expErr
		}
	}
	return count, nil
}

// Decr performs DECR key, undoing an IncrWithExpiry whose effect must be backed
// out (e.g. a counted operation that did not complete). The DECR error, if any,
// is returned unwrapped for the caller to log; callers treat it as best-effort.
func Decr(ctx context.Context, client valkeygo.Client, key string) error {
	return client.Do(ctx, client.B().Decr().Key(key).Build()).Error()
}
