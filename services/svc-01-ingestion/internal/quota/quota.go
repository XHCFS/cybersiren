// Package quota is svc-01's monthly ingestion-quota gate. It counts accepted
// emails per org per calendar month in Valkey (INCR quota:{org}:{YYYYMM}, with
// EXPIRE armed only when the counter is first created) and compares the count
// against organisations.monthly_ingestion_limit (NULL = unlimited).
package quota

import (
	"context"
	"fmt"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
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

	key := counterKey(orgID, time.Now().UTC())
	count, err := l.valkey.Do(ctx, l.valkey.B().Incr().Key(key).Build()).ToInt64()
	if err != nil {
		return true, fmt.Errorf("quota incr: %w", err) // fail-open
	}
	if count == 1 {
		// First write this month: arm the TTL so the counter self-evicts.
		if expErr := l.valkey.Do(ctx,
			l.valkey.B().Expire().Key(key).Seconds(counterTTLSeconds).Build(),
		).Error(); expErr != nil {
			return true, fmt.Errorf("quota expire: %w", expErr) // fail-open
		}
	}
	return count <= int64(*limit), nil
}

// counterKey builds the quota:{org_id}:{YYYYMM} Valkey key.
func counterKey(orgID int64, now time.Time) string {
	return fmt.Sprintf("quota:%d:%s", orgID, now.Format("200601"))
}
