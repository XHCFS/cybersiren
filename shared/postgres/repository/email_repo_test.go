package repository

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
		MessageID:   "msg-1",
		URLs:        []ParsedURL{{URL: "https://x.test"}},
		Attachments: []ParsedAttachment{{Library: db.UpsertParsedAttachmentParams{Sha256: "abc"}}},
		Recipients:  []ChildRecipient{{Address: "a@b.test", RecipientType: "to"}},
	}
	if in.MessageID != "msg-1" {
		t.Fatal("message_id not carried")
	}
	if in.URLs[0].URL != "https://x.test" {
		t.Fatal("url not carried")
	}
	if in.Attachments[0].Library.Sha256 != "abc" {
		t.Fatal("attachment sha256 not carried")
	}
}

// fakeQueries is an in-memory persistQueries that simulates the email_identities
// registry (ON CONFLICT DO NOTHING) and a monotonically-increasing internal_id
// BIGSERIAL, so the idempotency decision logic in persistParsedTx can be proven
// without a live DB. It records every InsertEmail / child insert / delete so the
// tests can assert how many emails rows were written.
type fakeQueries struct {
	nextInternalID int64
	identities     map[string]EmailKey // (org_id|message_id) -> canonical key
	emailInserts   int
	childInserts   int
	deletes        int
	// preRegister, when set, is invoked just before RegisterEmailIdentity decides
	// the claim — used to inject a racing winner so this ingestion loses the claim.
	preRegister func(f *fakeQueries)
}

func newFakeQueries() *fakeQueries {
	return &fakeQueries{identities: map[string]EmailKey{}}
}

func identityKey(orgID int64, messageID string) string {
	return strconv.FormatInt(orgID, 10) + "|" + messageID
}

func (f *fakeQueries) InsertEmail(_ context.Context, _ db.InsertEmailParams) (db.InsertEmailRow, error) {
	f.nextInternalID++
	f.emailInserts++
	return db.InsertEmailRow{
		InternalID: f.nextInternalID,
		FetchedAt:  pgtype.Timestamptz{Time: refTime, Valid: true},
	}, nil
}

func (f *fakeQueries) GetEmailIdentity(_ context.Context, arg db.GetEmailIdentityParams) (db.GetEmailIdentityRow, error) {
	key, ok := f.identities[identityKey(arg.OrgID, arg.MessageID)]
	if !ok {
		return db.GetEmailIdentityRow{}, pgx.ErrNoRows
	}
	return db.GetEmailIdentityRow{InternalID: key.InternalID, FetchedAt: key.FetchedAt}, nil
}

func (f *fakeQueries) RegisterEmailIdentity(_ context.Context, arg db.RegisterEmailIdentityParams) (int64, error) {
	if f.preRegister != nil {
		hook := f.preRegister
		f.preRegister = nil // fire once
		hook(f)
	}
	k := identityKey(arg.OrgID, arg.MessageID)
	if _, exists := f.identities[k]; exists {
		// ON CONFLICT DO NOTHING returned no row: the claim was lost.
		return 0, pgx.ErrNoRows
	}
	f.identities[k] = EmailKey{InternalID: arg.InternalID, FetchedAt: arg.FetchedAt}
	return arg.InternalID, nil
}

func (f *fakeQueries) DeleteEmailByKey(_ context.Context, _ db.DeleteEmailByKeyParams) error {
	f.deletes++
	return nil
}

func (f *fakeQueries) UpsertBareEnrichedThreat(_ context.Context, _ db.UpsertBareEnrichedThreatParams) (int64, error) {
	return 1, nil
}

func (f *fakeQueries) InsertEmailURL(_ context.Context, _ db.InsertEmailURLParams) (int64, error) {
	f.childInserts++
	return 1, nil
}

func (f *fakeQueries) UpsertParsedAttachment(_ context.Context, _ db.UpsertParsedAttachmentParams) (int64, error) {
	return 1, nil
}

func (f *fakeQueries) InsertEmailAttachment(_ context.Context, _ db.InsertEmailAttachmentParams) error {
	f.childInserts++
	return nil
}

func (f *fakeQueries) InsertEmailRecipient(_ context.Context, _ db.InsertEmailRecipientParams) (int64, error) {
	f.childInserts++
	return 1, nil
}

var refTime = pgtype.Timestamptz{}.Time

func samplePersist(msgID string) PersistParsedFull {
	return PersistParsedFull{
		MessageID:  msgID,
		URLs:       []ParsedURL{{URL: "http://evil.test/x"}},
		Recipients: []ChildRecipient{{Address: "a@b.test", RecipientType: "to"}},
	}
}

// TestPersistParsedTxIdempotentOnRepublish proves the migration-015 dedup: a
// second persist with the SAME message_id (a Kafka redelivery / re-publish)
// returns the SAME internal_id and inserts NO second emails row and NO second
// set of children — the registry short-circuits the whole write path.
func TestPersistParsedTxIdempotentOnRepublish(t *testing.T) {
	t.Parallel()
	f := newFakeQueries()
	in := samplePersist("dup-msg")

	first, err := persistParsedTx(context.Background(), f, 7, in)
	if err != nil {
		t.Fatalf("first persist: %v", err)
	}
	second, err := persistParsedTx(context.Background(), f, 7, in)
	if err != nil {
		t.Fatalf("second persist: %v", err)
	}

	if first.InternalID == 0 {
		t.Fatal("first persist returned zero internal_id")
	}
	if second.InternalID != first.InternalID {
		t.Fatalf("re-publish internal_id = %d, want same as first %d", second.InternalID, first.InternalID)
	}
	if f.emailInserts != 1 {
		t.Fatalf("emails inserted = %d, want exactly 1 across the re-publish", f.emailInserts)
	}
	// Children were written exactly once (1 url + 1 recipient on the first pass).
	if f.childInserts != 2 {
		t.Fatalf("child inserts = %d, want 2 (re-publish must skip children)", f.childInserts)
	}
}

// TestPersistParsedTxNoMessageIDInsertsEveryTime proves an empty message_id
// bypasses the registry entirely: each persist inserts a fresh emails row (NULL
// message_ids are intentionally not deduplicated — migration 015).
func TestPersistParsedTxNoMessageIDInsertsEveryTime(t *testing.T) {
	t.Parallel()
	f := newFakeQueries()
	in := samplePersist("")

	if _, err := persistParsedTx(context.Background(), f, 7, in); err != nil {
		t.Fatalf("first persist: %v", err)
	}
	if _, err := persistParsedTx(context.Background(), f, 7, in); err != nil {
		t.Fatalf("second persist: %v", err)
	}
	if f.emailInserts != 2 {
		t.Fatalf("emails inserted = %d, want 2 (no dedup for empty message_id)", f.emailInserts)
	}
}

// TestPersistParsedTxLostClaimDropsOrphan proves the race path: when another
// ingestion claims the message between our GetEmailIdentity miss and our
// RegisterEmailIdentity, we delete the orphan emails row we inserted and return
// the winner's internal_id, skipping our children.
func TestPersistParsedTxLostClaimDropsOrphan(t *testing.T) {
	t.Parallel()
	f := newFakeQueries()
	in := samplePersist("raced-msg")

	// Simulate a racing winner registering internal_id=999 just before our claim.
	winner := EmailKey{InternalID: 999, FetchedAt: pgtype.Timestamptz{Time: refTime, Valid: true}}
	f.preRegister = func(fq *fakeQueries) {
		fq.identities[identityKey(7, "raced-msg")] = winner
	}

	key, err := persistParsedTx(context.Background(), f, 7, in)
	if err != nil {
		t.Fatalf("persist with lost claim: %v", err)
	}
	if key.InternalID != 999 {
		t.Fatalf("returned internal_id = %d, want the winner's 999", key.InternalID)
	}
	if f.deletes != 1 {
		t.Fatalf("orphan deletes = %d, want 1 (the candidate we inserted then lost)", f.deletes)
	}
	if f.childInserts != 0 {
		t.Fatalf("child inserts = %d, want 0 (lost-claim path must skip children)", f.childInserts)
	}
}

// Compile-time assertion that *db.Queries satisfies persistQueries so the
// production path and the test fake stay in lockstep.
var _ persistQueries = (*db.Queries)(nil)
