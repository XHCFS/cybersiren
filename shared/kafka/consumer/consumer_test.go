package consumer

import "testing"

// recordOutcome mirrors the decision the Run loop makes for a single record
// based on the per-partition retry state. It exists so the bounded-retry /
// dead-letter decision can be exercised without standing up a Kafka broker:
// the live loop calls recordFailure/clearFailure exactly as modelled here.
type recordOutcome int

const (
	outcomeCommit     recordOutcome = iota // handler succeeded; commit + advance
	outcomeRetry                           // transient failure; rewind + retry
	outcomeDeadLetter                      // poison; dead-letter + commit to advance
)

// step replays one record through the consumer's retry bookkeeping and returns
// the outcome the Run loop would take. handlerErr reports whether the handler
// returned an error for this delivery.
func (c *Consumer) step(partition int32, offset int64, handlerErr bool) recordOutcome {
	if !handlerErr {
		c.clearFailure(partition)
		return outcomeCommit
	}
	fails := c.recordFailure(partition, offset)
	if fails > maxHandlerRetries {
		c.clearFailure(partition)
		return outcomeDeadLetter
	}
	return outcomeRetry
}

func newTestConsumer() *Consumer {
	return &Consumer{retries: make(map[int32]*stuckRecord)}
}

// TestPoisonRecordIsDeadLetteredAfterThreshold proves that a record whose
// handler always errors is retried at most maxHandlerRetries times and is then
// dead-lettered (offset committed / advanced) rather than retried forever.
func TestPoisonRecordIsDeadLetteredAfterThreshold(t *testing.T) {
	c := newTestConsumer()
	const partition int32 = 0
	const offset int64 = 42

	// Re-deliver the same poison record. The first maxHandlerRetries failures
	// must rewind-and-retry; the next must dead-letter.
	for i := 1; i <= maxHandlerRetries; i++ {
		if got := c.step(partition, offset, true); got != outcomeRetry {
			t.Fatalf("delivery %d: got outcome %d, want retry", i, got)
		}
	}
	if got := c.step(partition, offset, true); got != outcomeDeadLetter {
		t.Fatalf("delivery %d: got outcome %d, want dead-letter", maxHandlerRetries+1, got)
	}

	// After dead-lettering, the partition's retry state must be cleared so the
	// next record starts with a fresh budget and does not leak.
	if _, ok := c.retries[partition]; ok {
		t.Fatalf("retry state for partition %d not cleared after dead-letter", partition)
	}
}

// TestTransientFailureThenSuccessDoesNotSkip proves that a record that errors a
// few times (below the threshold) and then succeeds is committed normally and
// is never dead-lettered — transient resilience is preserved.
func TestTransientFailureThenSuccessDoesNotSkip(t *testing.T) {
	c := newTestConsumer()
	const partition int32 = 1
	const offset int64 = 7

	// A handful of transient failures, all under the budget.
	const transientFails = 3
	for i := 1; i <= transientFails; i++ {
		if got := c.step(partition, offset, true); got != outcomeRetry {
			t.Fatalf("transient failure %d: got outcome %d, want retry", i, got)
		}
	}

	// Then the redelivery succeeds: it must commit, not skip/dead-letter.
	if got := c.step(partition, offset, false); got != outcomeCommit {
		t.Fatalf("recovery delivery: got outcome %d, want commit", got)
	}

	// Success must clear the retry state.
	if _, ok := c.retries[partition]; ok {
		t.Fatalf("retry state for partition %d not cleared after success", partition)
	}
}

// TestRetryStateResetsWhenOffsetAdvances proves the per-partition tracker
// follows the current head record: when a different offset starts failing, the
// failure count restarts rather than carrying over, and only one entry per
// partition is ever kept.
func TestRetryStateResetsWhenOffsetAdvances(t *testing.T) {
	c := newTestConsumer()
	const partition int32 = 2

	// Record at offset 10 fails twice.
	if got := c.recordFailure(partition, 10); got != 1 {
		t.Fatalf("offset 10 first failure: got %d want 1", got)
	}
	if got := c.recordFailure(partition, 10); got != 2 {
		t.Fatalf("offset 10 second failure: got %d want 2", got)
	}

	// A different offset (the head advanced) must reset the count to 1.
	if got := c.recordFailure(partition, 11); got != 1 {
		t.Fatalf("offset 11 first failure: got %d want 1 (should reset)", got)
	}

	// Only one stuck record per partition is tracked.
	if len(c.retries) != 1 {
		t.Fatalf("retries map size: got %d want 1", len(c.retries))
	}
	if sr := c.retries[partition]; sr == nil || sr.offset != 11 || sr.failures != 1 {
		t.Fatalf("tracker not following head record: %+v", sr)
	}
}
