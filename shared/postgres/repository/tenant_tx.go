package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// ErrNoOrgContext is returned when a tenant-scoped transaction is requested
// without a valid organisation id. Every write to an RLS-forced table MUST be
// org-scoped (spec §16 D12 / G10), so a missing org id is a hard error rather
// than a silent full-table operation.
var ErrNoOrgContext = errors.New("repository: org_id is required for a tenant-scoped transaction")

// setCurrentOrgGUC is the statement that binds the per-transaction tenant
// boundary. Migration 018 enabled FORCE ROW LEVEL SECURITY with a
// tenant_isolation policy of the form:
//
//	current_setting('app.current_org_id', TRUE) IS NOT NULL
//	AND org_id = current_setting('app.current_org_id', TRUE)::BIGINT
//
// Until something sets this GUC, every policy denies access (the IS NOT NULL
// guard), so RLS was effectively bypassed only because the app connected as a
// BYPASSRLS/superuser role. Once the app connects as a non-bypass role (see
// the package doc), this SET LOCAL is what makes org isolation real.
//
// set_config(name, value, is_local=true) is used instead of a literal
// `SET LOCAL app.current_org_id = <n>` so the org id is passed as a bound
// parameter and never string-interpolated into SQL.
const setCurrentOrgGUC = `SELECT set_config('app.current_org_id', $1::text, true)`

// WithOrgTx runs fn inside a single pgx transaction that is scoped to orgID via
// the app.current_org_id GUC. The GUC is set with SET LOCAL semantics
// (set_config(..., true)), so it is automatically discarded when the
// transaction ends and never leaks onto a pooled connection reused by another
// tenant.
//
// fn receives a *db.Queries bound to the transaction (db.New(tx)); compose all
// multi-statement writes through it so they share the tenant boundary. The
// transaction is committed when fn returns nil and rolled back otherwise.
func WithOrgTx(ctx context.Context, pool *pgxpool.Pool, orgID int64, fn func(q *db.Queries) error) error {
	if pool == nil {
		return errors.New("repository: nil postgres pool")
	}
	if orgID <= 0 {
		return ErrNoOrgContext
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := SetOrgGUC(ctx, tx, orgID); err != nil {
		return err
	}

	if err := fn(db.New(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant tx: %w", err)
	}
	return nil
}

// SetOrgGUC binds app.current_org_id on an already-open transaction. Use this
// when a caller manages its own transaction lifecycle (e.g. SVC-08's decision
// writer) but still needs the RLS tenant boundary. orgID must be > 0.
//
// q must be a transaction handle (pgx.Tx) — the GUC uses SET LOCAL semantics
// and is only meaningful inside an explicit transaction.
func SetOrgGUC(ctx context.Context, tx pgx.Tx, orgID int64) error {
	if tx == nil {
		return errors.New("repository: nil transaction for org GUC")
	}
	if orgID <= 0 {
		return ErrNoOrgContext
	}
	if _, err := tx.Exec(ctx, setCurrentOrgGUC, fmt.Sprintf("%d", orgID)); err != nil {
		return fmt.Errorf("set app.current_org_id=%d: %w", orgID, err)
	}
	return nil
}
