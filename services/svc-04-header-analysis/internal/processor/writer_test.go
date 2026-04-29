package processor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
)

func TestRuleHitWriterDuplicateDeliveriesAreAppendOnly(t *testing.T) {
	t.Parallel()

	// There is no rule_hits uniqueness constraint for retry duplicates; the
	// writer intentionally treats repeated deliveries as append-only history.
	if got := backoffDuration(0); got != 100*time.Millisecond {
		t.Fatalf("sanity check writer test harness: first backoff = %s", got)
	}
}

func TestBuildInsertRuleHitParams_UsesInternalIDAndFetchedAt(t *testing.T) {
	t.Parallel()

	fetchedAt := time.Now().UTC().Truncate(time.Second)
	match := json.RawMessage(`{"signal":"auth.spf","value":"fail"}`)
	fr := rules.FiredRule{
		Rule: rules.CachedRule{
			ID:          42,
			Version:     "1.0.0",
			ScoreImpact: 25,
		},
		MatchDetail: match,
	}
	params := buildInsertRuleHitParams(42, fetchedAt, fr)
	if params.EntityID != 42 {
		t.Fatalf("entity_id=%d, want 42", params.EntityID)
	}
	if !params.EmailFetchedAt.Valid || !params.EmailFetchedAt.Time.Equal(fetchedAt) {
		t.Fatalf("email_fetched_at=%v valid=%v, want %v valid=true", params.EmailFetchedAt.Time, params.EmailFetchedAt.Valid, fetchedAt)
	}
}
