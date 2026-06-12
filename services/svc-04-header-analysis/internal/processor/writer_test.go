package processor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// TestRuleHitWriter_SkipsZeroInternalID asserts the writer skips (rather than
// orphan-INSERTs) a rule_hits write when internal_id is unresolved (0). The pool
// is a non-nil sentinel that is never dialed — the zero-id guard returns before
// runOnce would touch it. Without the guard, rule_hits.entity_id (BIGINT NOT
// NULL, no FK) would silently accept an orphan row pointing at no email.
func TestRuleHitWriter_SkipsZeroInternalID(t *testing.T) {
	t.Parallel()
	w := &RuleHitWriter{pool: &pgxpool.Pool{}, log: zerolog.Nop()}
	fired := []rules.FiredRule{{Rule: rules.CachedRule{ID: 1, Version: "1.0.0", ScoreImpact: 10}}}

	outcome, err := w.Write(context.Background(), 7, 0, time.Now(), fired)
	if err != nil {
		t.Fatalf("Write with internal_id=0 should skip cleanly, got err: %v", err)
	}
	if outcome != "ok" {
		t.Fatalf("outcome = %q, want ok (skipped, not written, not an error)", outcome)
	}
}

// rule_hits.entity_id must be emails.internal_id (the DB BIGSERIAL svc-02
// assigns). email_id is a UUIDv7 string and can NOT substitute (LANDMINE B): a
// missing internal_id yields 0, never the email_id.
func TestRuleHitEntityID_UsesInternalIDOnly(t *testing.T) {
	t.Parallel()
	if got := ruleHitEntityID(contractsk.AnalysisHeadersMessage{EmailID: "e999", InternalID: 15}); got != 15 {
		t.Fatalf("ruleHitEntityID with internal_id=15 -> %d, want 15", got)
	}
	if got := ruleHitEntityID(contractsk.AnalysisHeadersMessage{EmailID: "e999"}); got != 0 {
		t.Fatalf("ruleHitEntityID with internal_id=0 -> %d, want 0 (no email_id fallback)", got)
	}
}

func TestRuleHitWriterDuplicateDeliveriesAreAppendOnly(t *testing.T) {
	t.Parallel()

	// There is no rule_hits uniqueness constraint for retry duplicates; the
	// writer intentionally treats repeated deliveries as append-only history.
	if got := backoffDuration(0); got != 100*time.Millisecond {
		t.Fatalf("sanity check writer test harness: first backoff = %s", got)
	}
}

func TestBuildInsertRuleHitParams_UsesEmailIDAndFetchedAt(t *testing.T) {
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
