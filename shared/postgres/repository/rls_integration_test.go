//go:build integration

// RLS / tenant-isolation integration test (spec §16 D12, G10).
//
// Requires a migrated DB (migration 018 applied) reachable via APP_DATABASE_URL,
// where APP_DATABASE_URL points at the NON-BYPASS application role — NOT the
// superuser/owner used for migrations. A superuser bypasses RLS entirely, so
// the cross-org assertion below would silently pass-through and prove nothing.
// The test skips when APP_DATABASE_URL is unset so it never runs against the
// wrong role by accident.
//
// It proves the core G10 guarantee: with app.current_org_id bound to org A, a
// read can never see org B's rows.
package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

func appPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for RLS tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedOrg creates a throwaway organisation and returns its id. It uses the
// migration/owner pool because organisations is not RLS-forced and the app role
// may not hold INSERT on it; if only the app DSN is available the INSERT runs
// under it directly.
func seedOrg(t *testing.T, pool *pgxpool.Pool, slug string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx, `
INSERT INTO organisations (name, slug)
VALUES ($1, $2)
RETURNING id`, "RLS Test "+slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("seed org %s: %v", slug, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, id)
	})
	return id
}

// TestRLSCrossOrgReadReturnsZeroRows is the headline isolation proof: an email
// inserted under org B is invisible to a transaction scoped to org A.
func TestRLSCrossOrgReadReturnsZeroRows(t *testing.T) {
	pool := appPool(t)
	ctx := context.Background()

	orgA := seedOrg(t, pool, "org-a")
	orgB := seedOrg(t, pool, "org-b")

	fetchedAt := time.Now().UTC()

	// Insert one email under each org, each through its own org-scoped tx.
	var keyB db.InsertEmailRow
	insertEmail := func(orgID int64) db.InsertEmailRow {
		var out db.InsertEmailRow
		err := WithOrgTx(ctx, pool, orgID, func(q *db.Queries) error {
			row, qerr := q.InsertEmail(ctx, db.InsertEmailParams{
				FetchedAt: pgtype.Timestamptz{Time: fetchedAt, Valid: true},
				OrgID:     pgtype.Int8{Int64: orgID, Valid: true},
			})
			out = row
			return qerr
		})
		if err != nil {
			t.Fatalf("insert email for org %d: %v", orgID, err)
		}
		return out
	}
	_ = insertEmail(orgA)
	keyB = insertEmail(orgB)

	// Under org A's GUC, org B's email must be invisible.
	err := WithOrgTx(ctx, pool, orgA, func(q *db.Queries) error {
		_, qerr := q.GetEmailByInternalID(ctx, db.GetEmailByInternalIDParams{
			InternalID: keyB.InternalID,
			FetchedAt:  keyB.FetchedAt,
		})
		if qerr == nil {
			t.Fatalf("RLS violation: org A read org B's email %d", keyB.InternalID)
		}
		if qerr != pgx.ErrNoRows {
			return qerr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cross-org read tx: %v", err)
	}

	// Sanity: under org B's own GUC the row IS visible.
	err = WithOrgTx(ctx, pool, orgB, func(q *db.Queries) error {
		_, qerr := q.GetEmailByInternalID(ctx, db.GetEmailByInternalIDParams{
			InternalID: keyB.InternalID,
			FetchedAt:  keyB.FetchedAt,
		})
		return qerr
	})
	if err != nil {
		t.Fatalf("org B could not read its own email: %v", err)
	}
}

// TestWithOrgTxRejectsMissingOrg guards the application-layer invariant that no
// tenant-scoped tx may run without an org id.
func TestWithOrgTxRejectsMissingOrg(t *testing.T) {
	pool := appPool(t)
	err := WithOrgTx(context.Background(), pool, 0, func(*db.Queries) error { return nil })
	if err != ErrNoOrgContext {
		t.Fatalf("expected ErrNoOrgContext, got %v", err)
	}
}
