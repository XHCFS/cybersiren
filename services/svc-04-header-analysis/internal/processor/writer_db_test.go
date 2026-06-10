package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
)

// TestRuleHitWriter_InsertsRows is the pgx-backed proof that RuleHitWriter.Write
// actually lands rule_hits rows via the real sqlc InsertRuleHit path (not a
// stub). It is guarded two ways:
//
//   - testing.Short() skips it, so `go test -short` (the no-infra self-check and
//     the CI test-short gate) never needs Postgres; and
//   - it skips when no DB DSN is provided, so a developer running `make test`
//     without infra up does not get a hard failure.
//
// It runs for real at the batch gate under `make test` (go test -race, no
// -short) with infra up. DATABASE_URL is the migration/owner DSN; we prefer it
// so the insert is exercised end-to-end regardless of the RLS-role rollout
// state (the writer still issues SET LOCAL app.current_org_id either way).
func TestRuleHitWriter_InsertsRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test under -short")
	}

	dsn := firstNonEmptyEnv("DATABASE_URL", "APP_DATABASE_URL", "CYBERSIREN_DB__DSN")
	if dsn == "" {
		t.Skip("set DATABASE_URL (or APP_DATABASE_URL) to run the rule_hits write test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	defer pool.Close()
	if pingErr := pool.Ping(ctx); pingErr != nil {
		t.Skipf("database not reachable (%v); skipping", pingErr)
	}

	// Seed an org + a rule the FK (rule_hits.rule_id -> rules.id) can point at.
	orgID := seedTestOrg(ctx, t, pool)
	ruleID := seedTestRule(ctx, t, pool, orgID)

	writer := NewRuleHitWriter(pool, 1, zerolog.Nop())

	fetchedAt := time.Now().UTC().Truncate(time.Microsecond)
	internalID := time.Now().UnixNano() // unique-ish synthetic emails.internal_id
	fired := []rules.FiredRule{
		{
			Rule:        rules.CachedRule{ID: ruleID, Name: "svc04.test.rule", Version: "1.0.0", ScoreImpact: 25},
			MatchDetail: json.RawMessage(`{"signal":"auth.spf","value":"fail"}`),
		},
		{
			Rule:        rules.CachedRule{ID: ruleID, Name: "svc04.test.rule", Version: "1.0.0", ScoreImpact: 15},
			MatchDetail: json.RawMessage(`{"signal":"structural.has_form","value":true}`),
		},
	}

	outcome, writeErr := writer.Write(ctx, orgID, internalID, fetchedAt, fired)
	if writeErr != nil {
		t.Fatalf("Write returned error: %v (outcome=%s)", writeErr, outcome)
	}
	if outcome != "ok" {
		t.Fatalf("outcome = %q, want ok", outcome)
	}

	// Verify both rows committed for this synthetic entity_id.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM rule_hits WHERE entity_type = 'email' AND entity_id = $1 AND rule_id = $2`,
		internalID, ruleID,
	).Scan(&count); err != nil {
		t.Fatalf("count rule_hits: %v", err)
	}
	if count != 2 {
		t.Fatalf("rule_hits rows for entity_id=%d = %d, want 2", internalID, count)
	}

	// Empty fired list opens no transaction and writes nothing.
	outcome, writeErr = writer.Write(ctx, orgID, internalID, fetchedAt, nil)
	if writeErr != nil || outcome != "ok" {
		t.Fatalf("empty-fired Write: outcome=%q err=%v, want ok/nil", outcome, writeErr)
	}

	// Cleanup: remove the rows we created (best effort).
	_, _ = pool.Exec(ctx, `DELETE FROM rule_hits WHERE entity_id = $1`, internalID)
	_, _ = pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, ruleID)
	_, _ = pool.Exec(ctx, `DELETE FROM organisations WHERE id = $1`, orgID)
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func seedTestOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	// Slug must satisfy chk_organisations_slug_format (^[a-z0-9]([a-z0-9-]*[a-z0-9])?$),
	// so use a digits-only nanosecond suffix — no dot from a fractional-seconds format.
	slug := fmt.Sprintf("svc04-rulehit-%d", time.Now().UnixNano())
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO organisations (name, slug) VALUES ($1, $2) RETURNING id`,
		"svc04 rule_hits test", slug,
	).Scan(&id); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return id
}

func seedTestRule(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID int64) int64 {
	t.Helper()
	logic := json.RawMessage(`{"category":"auth","expr":{"signal":"auth.spf","op":"eq","value":"fail"}}`)
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO rules (org_id, name, description, version, status, target, score_impact, logic)
		 VALUES ($1, $2, $3, '1.0.0', 'active', 'header', 25, $4)
		 RETURNING id`,
		orgID, "svc04.test.rule", "rule_hits write test", logic,
	).Scan(&id); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	return id
}
