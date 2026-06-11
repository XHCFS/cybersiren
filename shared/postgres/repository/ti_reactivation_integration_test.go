//go:build integration

// TI indicator reactivation regression test (finding #13).
//
// Guards the UpsertTIIndicator ON CONFLICT ... DO UPDATE path: a re-seen
// indicator must be reactivated (is_active = TRUE), otherwise an indicator that
// briefly dropped out of a feed and was deactivated by DeactivateStaleFeedIndicators
// stays invisible to detection forever.
//
// Requires a migrated DB reachable via TI_DATABASE_URL (any role with write
// access to feeds/ti_indicators — RLS is not exercised here). The test skips
// when TI_DATABASE_URL is unset so it never runs against the wrong DB by accident.
package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
)

func tiPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TI_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TI_DATABASE_URL to a migrated DB DSN for TI reactivation tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("ti pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestUpsertTIIndicator_ReactivatesDeactivatedIndicator drives the three-cycle
// flap scenario through the real query: insert active, let it go stale and be
// deactivated, then re-seen → it must come back active.
func TestUpsertTIIndicator_ReactivatesDeactivatedIndicator(t *testing.T) {
	pool := tiPool(t)
	ctx := context.Background()

	// Seed a throwaway feed; ti_indicators.feed_id REFERENCES feeds(id).
	var feedID int64
	err := pool.QueryRow(ctx, `
INSERT INTO feeds (name, feed_type, enabled)
VALUES ($1, 'threat_intel', TRUE)
RETURNING id`, "ti-reactivation-test-"+time.Now().Format("150405.000000")).Scan(&feedID)
	if err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM ti_indicators WHERE feed_id = $1`, feedID)
		_, _ = pool.Exec(ctx, `DELETE FROM feeds WHERE id = $1`, feedID)
	})

	repo := NewTIRepository(pool, zerolog.Nop(), nil)

	const flapping = "flapping.example.com"
	const stable = "stable.example.com"

	domainIndicator := func(value string) TIIndicator {
		return TIIndicator{
			FeedID:         feedID,
			FeedName:       "ti-reactivation-test",
			IndicatorType:  db.TiIndicatorTypeDomain,
			IndicatorValue: value,
			ThreatType:     "phishing",
			ThreatTags:     []string{"test"},
			RiskScore:      80,
			SourceID:       "test",
		}
	}

	isActive := func(value string) bool {
		var active bool
		qErr := pool.QueryRow(ctx, `
SELECT is_active FROM ti_indicators
WHERE feed_id = $1 AND indicator_type = 'domain' AND indicator_value = $2`, feedID, value).Scan(&active)
		if qErr != nil {
			t.Fatalf("query is_active for %q: %v", value, qErr)
		}
		return active
	}

	// Cycle 1: both domains present → both active.
	if _, err := repo.BulkUpsertIndicators(ctx, []TIIndicator{
		domainIndicator(flapping),
		domainIndicator(stable),
	}); err != nil {
		t.Fatalf("cycle 1 upsert: %v", err)
	}
	if !isActive(flapping) {
		t.Fatalf("cycle 1: flapping domain should be active")
	}

	// Allow the next cycle's startedAt to strictly exceed cycle 1's last_seen
	// so the omitted row is older than the deactivation cutoff.
	time.Sleep(10 * time.Millisecond)

	// Cycle 2: feed omits the flapping domain (but still has the stable one, so
	// the batch is non-empty and deactivation runs for this feed) → flapping is
	// now stale and gets deactivated.
	if _, err := repo.BulkUpsertIndicators(ctx, []TIIndicator{
		domainIndicator(stable),
	}); err != nil {
		t.Fatalf("cycle 2 upsert: %v", err)
	}
	if isActive(flapping) {
		t.Fatalf("cycle 2: flapping domain should have been deactivated")
	}

	// Cycle 3: the flapping domain reappears → ON CONFLICT DO UPDATE must
	// reactivate it. Before the fix it stayed is_active = FALSE forever.
	if _, err := repo.BulkUpsertIndicators(ctx, []TIIndicator{
		domainIndicator(flapping),
		domainIndicator(stable),
	}); err != nil {
		t.Fatalf("cycle 3 upsert: %v", err)
	}
	if !isActive(flapping) {
		t.Fatalf("cycle 3: re-seen flapping domain must be reactivated (is_active = TRUE)")
	}
}
