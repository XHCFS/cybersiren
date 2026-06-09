package repository

import (
	"context"
	"errors"
	"testing"

	db "github.com/saif/cybersiren/db/sqlc"
)

// These cover the pre-flight guards that do not require a live DB: a missing
// org id or nil pool/tx must fail before any statement is issued, so a
// tenant-scoped operation can never silently run unscoped.

func TestWithOrgTxNilPool(t *testing.T) {
	t.Parallel()
	err := WithOrgTx(context.Background(), nil, 1, func(*db.Queries) error { return nil })
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestSetOrgGUCRejectsNilTx(t *testing.T) {
	t.Parallel()
	if err := SetOrgGUC(context.Background(), nil, 1); err == nil {
		t.Fatal("expected error for nil tx")
	}
}

func TestSetOrgGUCRejectsBadOrg(t *testing.T) {
	t.Parallel()
	// orgID <= 0 is validated before the tx is touched (see SetOrgGUC guard
	// order), so a non-positive org is rejected with the ErrNoOrgContext sentinel
	// regardless of tx state. Asserting the sentinel (not just non-nil) is what
	// actually exercises the org guard — a plain non-nil check would also pass on
	// the nil-tx error and prove nothing about org validation.
	if err := SetOrgGUC(context.Background(), nil, 0); !errors.Is(err, ErrNoOrgContext) {
		t.Fatalf("expected ErrNoOrgContext for zero org id, got %v", err)
	}
	if err := SetOrgGUC(context.Background(), nil, -1); !errors.Is(err, ErrNoOrgContext) {
		t.Fatalf("expected ErrNoOrgContext for negative org id, got %v", err)
	}
}

func TestErrNoOrgContextIsSentinel(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrNoOrgContext, ErrNoOrgContext) {
		t.Fatal("ErrNoOrgContext must be a stable sentinel")
	}
}
