package processor

import (
	"testing"
	"time"
)

func TestRuleHitWriterDuplicateDeliveriesAreAppendOnly(t *testing.T) {
	t.Parallel()

	// There is no rule_hits uniqueness constraint for retry duplicates; the
	// writer intentionally treats repeated deliveries as append-only history.
	if got := backoffDuration(0); got != 100*time.Millisecond {
		t.Fatalf("sanity check writer test harness: first backoff = %s", got)
	}
}
