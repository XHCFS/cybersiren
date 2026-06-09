package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// These cover the pre-flight guards on the SVC-02 persist path that do not need
// a live DB: a nil pool or a missing org must fail before any statement runs, so
// the six write-groups can never execute outside a tenant boundary (G10). The
// cross-org / RLS proof against a real DB lives in rls_integration_test.go.

func TestPersistParsedNilPool(t *testing.T) {
	t.Parallel()
	var r *EmailRepository
	if _, err := r.PersistParsed(context.Background(), 1, PersistParsedFull{}); err == nil {
		t.Fatal("expected error for nil repository")
	}
	r = NewEmailRepository(nil)
	if _, err := r.PersistParsed(context.Background(), 1, PersistParsedFull{}); err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestPersistParsedRejectsMissingOrg(t *testing.T) {
	t.Parallel()
	// A real (non-nil) pool is needed to reach the orgID<=0 guard: WithOrgTx
	// checks the nil-pool case first, so passing nil would short-circuit on the
	// pool error and never exercise org rejection. pgxpool.New does not connect
	// eagerly (pool_min_conns defaults to 0), so a dummy DSN yields a live *Pool
	// without touching the network, and the orgID<=0 guard returns before any
	// query — a write with no org is unroutable under RLS.
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/db")
	if err != nil {
		t.Fatalf("construct lazy pool: %v", err)
	}
	defer pool.Close()
	r := NewEmailRepository(pool)
	if _, err := r.PersistParsed(context.Background(), 0, PersistParsedFull{}); !errors.Is(err, ErrNoOrgContext) {
		t.Fatalf("expected ErrNoOrgContext for org_id = 0, got %v", err)
	}
}

// TestPersistParsedFullShape is a compile-time + zero-value sanity check that
// the input model wires onto the generated sqlc params the repo composes, so a
// drift in the generated layer surfaces here rather than at runtime.
func TestPersistParsedFullShape(t *testing.T) {
	t.Parallel()
	in := PersistParsedFull{
		Email:       db.InsertEmailParams{},
		URLs:        []ParsedURL{{URL: "https://x.test"}},
		Attachments: []ParsedAttachment{{Library: db.UpsertParsedAttachmentParams{Sha256: "abc"}}},
		Recipients:  []ChildRecipient{{Address: "a@b.test", RecipientType: "to"}},
	}
	if in.URLs[0].URL != "https://x.test" {
		t.Fatal("url not carried")
	}
	if in.Attachments[0].Library.Sha256 != "abc" {
		t.Fatal("attachment sha256 not carried")
	}
}
