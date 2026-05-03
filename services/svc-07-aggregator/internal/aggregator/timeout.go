package aggregator

import (
	"context"
	"strconv"
	"time"
)

// Sweeper is the background goroutine that emits partial emails.scored
// messages for buckets whose first message arrived ≥ TimeoutSecs ago.
//
// It runs alongside the consumer Handlers and is the only mechanism that
// guarantees an emails.scored emit even when no further score messages
// arrive for an email_id (see brief §2.5 — option 2).
//
// Multiple SVC-07 instances run concurrently; publish coordination uses the
// same Valkey NX lock key as Handle (aggregator:publock:{org_id}:{email_id}).
type Sweeper struct {
	agg *Aggregator
}

// NewSweeper constructs a Sweeper bound to an Aggregator. Use Run to start
// the background goroutine.
func NewSweeper(agg *Aggregator) *Sweeper {
	return &Sweeper{agg: agg}
}

// Run blocks until ctx is cancelled, sweeping at the aggregator's
// configured SweepInterval. It is safe to call from a goroutine; on ctx
// cancellation Run returns nil.
func (s *Sweeper) Run(ctx context.Context) error {
	if s == nil || s.agg == nil {
		return nil
	}
	t := time.NewTicker(s.agg.cfg.SweepInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.tick(ctx)
		}
	}
}

// tick runs one sweep pass. It is exported test-only as a method on the
// Aggregator for golden-tests; this method here is the production entry.
func (s *Sweeper) tick(ctx context.Context) {
	a := s.agg

	threshold := a.now().Add(-time.Duration(a.cfg.TimeoutSecs) * time.Second)
	bucketCount := 0

	scanErr := a.store.Scan(ctx, keyPrefix+"*", func(keys []string) bool {
		for _, key := range keys {
			if isEmailAggregatorKey(key) {
				bucketCount++
			}
		}
		for _, key := range keys {
			if ctx.Err() != nil {
				return false
			}
			if !isEmailAggregatorKey(key) {
				continue
			}
			s.processKey(ctx, key, threshold)
		}
		return true
	})
	if scanErr != nil {
		a.log.Debug().Err(scanErr).Msg("sweeper scan failed")
	}
	if a.metrics != nil && a.metrics.ActiveBuckets != nil {
		a.metrics.ActiveBuckets.Set(float64(bucketCount))
	}
}

// processKey decides whether `key` has aged past the timeout threshold and,
// if so, attempts to acquire the publish lock and emit a partial
// emails.scored. Lock acquisition failure is benign (another instance is
// handling it).
func (s *Sweeper) processKey(ctx context.Context, key string, threshold time.Time) {
	a := s.agg

	startedRaw, ok, err := a.store.HGet(ctx, key, fieldStartedAt)
	if err != nil || !ok || startedRaw == "" {
		return
	}
	startedAt := parseStartedAt(startedRaw)
	if startedAt.IsZero() || startedAt.After(threshold) {
		return // not stale enough
	}

	orgIDKey, emailID, ok := parseAggregatorBucketKey(key)
	if !ok {
		return
	}

	lockKey := publishLockKey(orgIDKey, emailID)
	got, err := a.store.SetNXEX(ctx, lockKey, a.cfg.PublishLockTTLSecs, "1")
	if err != nil || !got {
		return
	}

	state, err := a.store.HGetAll(ctx, key)
	if err != nil {
		_ = a.store.Del(ctx, lockKey)
		return
	}
	orgID, _ := strconv.ParseInt(state[fieldOrgID], 10, 64)
	if orgID != 0 && orgID != orgIDKey {
		a.log.Warn().
			Int64("email_id", emailID).
			Int64("key_org", orgIDKey).
			Int64("state_org", orgID).
			Msg("sweeper: org_id mismatch between key and hash; using key org")
	}
	orgID = orgIDKey

	// If the plan never arrived we cannot package a meaningful partial
	// (we don't know which scores were expected). Drop the lock and let
	// the bucket TTL out — a "no plan" bucket is a parser bug, not a
	// pipeline timeout.
	if _, ok := state[fieldPlan]; !ok {
		a.log.Warn().Int64("email_id", emailID).Msg("sweeper: bucket aged out without plan; dropping")
		_ = a.store.Del(ctx, lockKey)
		return
	}

	if err := a.publishAndCleanup(ctx, orgID, emailID, state, startedAt, true /*timeout*/); err != nil {
		a.log.Warn().Err(err).Int64("email_id", emailID).Msg("sweeper publish failed; releasing lock for retry")
		_ = a.store.Del(ctx, lockKey)
		a.bumpPublishError("publish")
		return
	}
	a.observeMessage("__sweep__", "partial")
}

// isEmailAggregatorKey returns true for bucket keys aggregator:{org}:{email}.
func isEmailAggregatorKey(key string) bool {
	_, _, ok := parseAggregatorBucketKey(key)
	return ok
}
