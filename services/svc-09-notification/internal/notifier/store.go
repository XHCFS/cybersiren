package notifier

import (
	"context"
	"fmt"

	valkeygo "github.com/valkey-io/valkey-go"

	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

// RateLimitTTLSeconds is the per-(org, campaign) alert window, per ARCH-SPEC §3
// Redis key table: notif:{org_id}:{campaign_id} STRING counter, 3600s TTL,
// "INCR on each alert, block if > 1".
const RateLimitTTLSeconds = 3600

// RateLimiter decides whether an alert for a given (org, campaign) bucket is
// allowed under the per-campaign-per-hour cap. Allow performs an atomic
// claim: it returns true at most once per bucket per TTL window.
type RateLimiter interface {
	// Allow returns true if this is the first alert for key within the current
	// window (and records the claim), false if the window already has one.
	Allow(ctx context.Context, key string) (bool, error)
}

// RateLimitKey builds the notif:{org_id}:{campaign_id} Redis key. When a
// verdict has no campaign (campaign_id is nil — e.g. a single non-campaign
// email), the email id is used as the bucket discriminator so per-email alerts
// are still de-duplicated across redeliveries instead of collapsing every
// non-campaign alert for the org into one shared bucket.
func RateLimitKey(orgID int64, campaignID *int64, emailID string) string {
	if campaignID != nil {
		return fmt.Sprintf("notif:%d:%d", orgID, *campaignID)
	}
	return fmt.Sprintf("notif:%d:email-%s", orgID, emailID)
}

// ValkeyRateLimiter implements RateLimiter over valkey-go using a single
// atomic SET key "1" NX EX 3600. The first writer in a window gets OK and is
// allowed (with the 3600s TTL claimed atomically); subsequent writers get nil
// and are blocked. Because the claim and the TTL land in one command there is
// no window in which the counter key can persist without a TTL, so a crashed
// or partial round-trip can never permanently suppress a bucket's alerts.
type ValkeyRateLimiter struct {
	client valkeygo.Client
	ttl    int
}

// NewValkeyRateLimiter wraps an existing valkey-go client. A nil client yields
// a limiter whose Allow always errors, so callers must guard on Valkey
// availability (the notifier degrades to allow-on-error to avoid dropping
// alerts when Redis is down).
func NewValkeyRateLimiter(client valkeygo.Client) *ValkeyRateLimiter {
	return &ValkeyRateLimiter{client: client, ttl: RateLimitTTLSeconds}
}

func (r *ValkeyRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	if r == nil || r.client == nil {
		return false, fmt.Errorf("notifier: nil valkey client")
	}
	// Atomic claim: SET key "1" NX EX ttl. The first writer in the window gets
	// OK (allow) and the TTL is armed in the same command; subsequent writers
	// get a nil reply (block). There is no INCR-then-EXPIRE gap in which a key
	// could be left without a TTL. The shared primitive folds the IsValkeyNil
	// reply into allowed=false/err=nil (block); any other error is surfaced for
	// our own wrapping so the notifier's degrade-to-allow-on-error policy and
	// error text stay unchanged.
	allowed, err := sharedvalkey.Claim(ctx, r.client, key, int64(r.ttl))
	if err != nil {
		return false, fmt.Errorf("set %s: %w", key, err)
	}
	return allowed, nil
}
