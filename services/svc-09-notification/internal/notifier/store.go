package notifier

import (
	"context"
	"fmt"

	valkeygo "github.com/valkey-io/valkey-go"
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
func RateLimitKey(orgID int64, campaignID *int64, emailID int64) string {
	if campaignID != nil {
		return fmt.Sprintf("notif:%d:%d", orgID, *campaignID)
	}
	return fmt.Sprintf("notif:%d:email-%d", orgID, emailID)
}

// ValkeyRateLimiter implements RateLimiter over valkey-go using the spec's
// INCR + EXPIRE counter. The first INCR in a window returns 1 and arms a 3600s
// TTL; subsequent INCRs within the window return > 1 and are blocked. The TTL
// is only (re)armed on the first hit, so a steady stream of suppressed alerts
// cannot keep the window alive forever.
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
	n, err := r.client.Do(ctx, r.client.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return false, fmt.Errorf("incr %s: %w", key, err)
	}
	if n == 1 {
		// First alert in the window: arm the TTL. A failure to set the TTL is
		// non-fatal for this decision (the key would otherwise persist), but we
		// surface it so the caller can log; the alert is still allowed.
		if exErr := r.client.Do(ctx,
			r.client.B().Expire().Key(key).Seconds(int64(r.ttl)).Build(),
		).Error(); exErr != nil {
			return true, fmt.Errorf("expire %s: %w", key, exErr)
		}
		return true, nil
	}
	return false, nil
}
