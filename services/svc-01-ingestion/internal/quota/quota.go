// Package quota is svc-01's monthly ingestion-quota gate. It counts accepted
// emails per org per calendar month in Valkey (INCR quota:{org}:{YYYYMM}, with
// EXPIRE armed only when the counter is first created) and compares the count
// against organisations.monthly_ingestion_limit (NULL = unlimited).
package quota

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	valkeygo "github.com/valkey-io/valkey-go"

	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

// counterTTLSeconds bounds a month's counter key so a long-idle org's stale
// counters self-evict. Two months of slack past the month boundary is ample.
const counterTTLSeconds = 70 * 24 * 60 * 60

// Limiter enforces the monthly ingestion quota. A nil Valkey client disables
// quota enforcement (Allow always permits) so a cache outage never blocks
// ingestion — the limit is a soft guard, not a security boundary.
type Limiter struct {
	valkey valkeygo.Client
}

// New builds a Limiter over the Valkey client. valkey may be nil (quota
// disabled / fail-open).
func New(valkey valkeygo.Client) *Limiter {
	return &Limiter{valkey: valkey}
}

// Allow increments the org's current-month counter and reports whether it stays
// within limit. limit is organisations.monthly_ingestion_limit; a nil limit (or
// <= 0) means unlimited and always allows. On any Valkey error it fails open
// (allow) so a cache blip cannot wedge ingestion.
//
// The EXPIRE is armed only on the INCR that returns 1 (the key's first write in
// the month), so the TTL is set exactly once and a mid-month counter is never
// reset by a later EXPIRE.
func (l *Limiter) Allow(ctx context.Context, orgID int64, limit *int32) (bool, error) {
	if limit == nil || *limit <= 0 {
		return true, nil // unlimited
	}
	if l.valkey == nil {
		return true, nil // quota disabled (fail-open)
	}

	// INCR the month counter and arm the TTL only on the first write (count==1),
	// so the TTL is set exactly once and a mid-month counter is never reset by a
	// later EXPIRE. Either op erroring fails open (allow) so a cache blip cannot
	// wedge ingestion. The shared primitive returns the post-increment count and
	// the raw INCR error (count==0) or EXPIRE error (count already incremented);
	// we map both onto the existing fail-open messages.
	key := counterKey(orgID, time.Now().UTC())
	count, err := sharedvalkey.IncrWithExpiry(ctx, l.valkey, key, counterTTLSeconds)
	if err != nil {
		if count == 0 {
			return true, fmt.Errorf("quota incr: %w", err) // fail-open
		}
		return true, fmt.Errorf("quota expire: %w", err) // fail-open
	}
	return count <= int64(*limit), nil
}

// Refund decrements the org's current-month counter, undoing an Allow that did
// not result in a published email (e.g. a publish failure after the quota was
// consumed). It is best-effort and fail-open: a no-op when the limit is nil/<=0
// (unlimited orgs were never counted) or when Valkey is unavailable, and a DECR
// error is logged but never surfaced. The counter is monotonic within a month
// otherwise, so this keeps it honest without ever being able to wedge ingestion.
func (l *Limiter) Refund(ctx context.Context, orgID int64, limit *int32) error {
	if limit == nil || *limit <= 0 {
		return nil // unlimited orgs are never counted; nothing to refund
	}
	if l.valkey == nil {
		return nil // quota disabled; Allow never incremented
	}
	key := counterKey(orgID, time.Now().UTC())
	if err := sharedvalkey.Decr(ctx, l.valkey, key); err != nil {
		log.Warn().Err(err).Int64("org_id", orgID).Msg("quota refund failed (best-effort)")
	}
	return nil
}

// counterKey builds the quota:{org_id}:{YYYYMM} Valkey key.
func counterKey(orgID int64, now time.Time) string {
	return fmt.Sprintf("quota:%d:%s", orgID, now.Format("200601"))
}
