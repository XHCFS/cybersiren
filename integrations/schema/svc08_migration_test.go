//go:build integration

// Requires DATABASE_URL and a migrated DB (`make db-migrate` against the same DSN).
package schema

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestVerdictsKafkaVerdictWireColumn(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("set DATABASE_URL for integration schema checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var name string
	err = pool.QueryRow(ctx, `
SELECT column_name
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'verdicts'
  AND column_name = 'kafka_verdict_wire'
`).Scan(&name)
	if err != nil {
		t.Fatalf("kafka_verdict_wire column: %v (run migrations through 029)", err)
	}
}

func TestPipelineVerdictUniqueIndex(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("set DATABASE_URL for integration schema checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var (
		n        int
		indexDef string
	)
	err = pool.QueryRow(ctx, `
SELECT COUNT(*), COALESCE(MAX(indexdef), '')
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'verdicts'
  AND indexname = 'uq_verdicts_pipeline_email_partition'
`).Scan(&n, &indexDef)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected uq_verdicts_pipeline_email_partition on verdicts, got count=%d", n)
	}
	def := strings.ToLower(indexDef)
	for _, want := range []string{
		"where",
		"entity_type = 'email'",
		"email_fetched_at is not null",
		"source = any",
	} {
		if !strings.Contains(def, want) {
			t.Fatalf("index predicate missing %q in definition: %s", want, indexDef)
		}
	}
}
