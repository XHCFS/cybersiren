package store

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

func TestInt4ToInt(t *testing.T) {
	if got := int4ToInt(pgtype.Int4{}); got != 0 {
		t.Fatalf("invalid Int4 = %d, want 0", got)
	}
	if got := int4ToInt(pgtype.Int4{Int32: 73, Valid: true}); got != 73 {
		t.Fatalf("valid Int4 = %d, want 73", got)
	}
}

func TestNilIfEmpty(t *testing.T) {
	if nilIfEmpty(nil) != nil {
		t.Fatal("nil slice should stay nil")
	}
	if nilIfEmpty([]byte{}) != nil {
		t.Fatal("empty slice should become nil")
	}
	b := []byte(`{"a":1}`)
	if got := nilIfEmpty(b); !bytes.Equal(got, b) {
		t.Fatalf("non-empty slice should be returned verbatim, got %s", got)
	}
}

func TestNewRepoStore_NilPool(t *testing.T) {
	if NewRepoStore(nil) != nil {
		t.Fatal("NewRepoStore(nil) must return nil")
	}
}

// TestRepoStore_RoundTrip exercises the RepoStore against a live Postgres. It is
// a DB-integration test: it is skipped under `go test -short` (the unit gate)
// and additionally skips when APP_DATABASE_URL (the non-bypass app role DSN) is
// unset, so it only runs at the batch gate with infra up. It proves the four
// org-scoped writes round-trip through RLS.
func TestRepoStore_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test in -short mode")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for store integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	s := NewRepoStore(pool)
	const orgID = int64(1)
	sha := "0000000000000000000000000000000000000000000000000000000000000005"

	// A hash that was never observed must be a clean miss (no error).
	v, err := s.GetHashVerdict(ctx, orgID, sha+"ffff")
	if err != nil {
		t.Fatalf("hash miss errored: %v", err)
	}
	if v.Found {
		t.Fatal("unobserved hash should not be Found")
	}

	// Flag a malicious hash, then read it back.
	if err := s.FlagMalicious(ctx, orgID, sha, 90, []string{"malware"}); err != nil {
		t.Fatalf("flag malicious: %v", err)
	}
	got, err := s.GetHashVerdict(ctx, orgID, sha)
	if err != nil {
		t.Fatalf("read flagged hash: %v", err)
	}
	if !got.Found || !got.IsMalicious || got.RiskScore != 90 {
		t.Fatalf("flagged verdict mismatch: %+v", got)
	}

	// VT cache round-trip on the resolved library id.
	if err := s.CacheVT(ctx, orgID, got.ID, time.Now().UTC(), VTCacheInput{
		MaliciousVotes: 4,
		Raw:            []byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":4}}}}`),
	}, time.Hour); err != nil {
		t.Fatalf("cache vt: %v", err)
	}
	cached, err := s.GetFreshVT(ctx, orgID, got.ID)
	if err != nil {
		t.Fatalf("read vt cache: %v", err)
	}
	if !cached.Found || cached.MaliciousVotes != 4 {
		t.Fatalf("vt cache mismatch: %+v", cached)
	}
}

// TestRepoStore_UpdateEmailAttachmentScore_KeysOnInternalID is the regression
// guard for the two-id write-back bug (G17): the parser stores
// email_attachments.email_id = emails.internal_id (the DB BIGSERIAL surrogate),
// NOT the logical Meta.EmailID. SVC-05 must key the risk_score UPDATE on that
// internal_id. This test seeds one emails row + one email_attachments link via
// the production queries, then proves:
//
//	(1) keying on the real internal_id affects exactly 1 row, and
//	(2) keying on the logical email_id (a large svc-01-style nanosecond id that
//	    never equals the small BIGSERIAL) affects 0 rows.
//
// Before the fix, internalIDOf() returned Meta.EmailID and the write-back
// silently matched 0 rows. It is a DB-integration test: skipped under -short and
// when APP_DATABASE_URL (the non-bypass app role DSN) is unset.
func TestRepoStore_UpdateEmailAttachmentScore_KeysOnInternalID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test in -short mode")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for store integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	s := NewRepoStore(pool)
	const orgID = int64(1)
	fetchedAt := time.Now().UTC()
	ts := pgtype.Timestamptz{Time: fetchedAt, Valid: true}
	sha := "0000000000000000000000000000000000000000000000000000000000000515"

	// Seed an emails row (RETURNING the BIGSERIAL internal_id), an
	// attachment_library row, and the email_attachments link keyed on the real
	// internal_id — all through the production queries inside the tenant tx so
	// RLS and the FK to emails(internal_id, fetched_at) are satisfied.
	var internalID, attachmentID int64
	err = repository.WithOrgTx(ctx, pool, orgID, func(q *dbsqlc.Queries) error {
		row, qerr := q.InsertEmail(ctx, dbsqlc.InsertEmailParams{
			FetchedAt: ts,
			OrgID:     pgtype.Int8{Int64: orgID, Valid: true},
			MessageID: pgtype.Text{String: "<p2.1-writeback-test@cybersiren>", Valid: true},
		})
		if qerr != nil {
			return qerr
		}
		internalID = row.InternalID

		id, qerr := q.UpsertParsedAttachment(ctx, dbsqlc.UpsertParsedAttachmentParams{Sha256: sha})
		if qerr != nil {
			return qerr
		}
		attachmentID = id

		return q.InsertEmailAttachment(ctx, dbsqlc.InsertEmailAttachmentParams{
			EmailID:        internalID,
			EmailFetchedAt: ts,
			AttachmentID:   attachmentID,
			Filename:       pgtype.Text{String: "invoice.pdf", Valid: true},
			OrgID:          pgtype.Int8{Int64: orgID, Valid: true},
		})
	})
	if err != nil {
		t.Fatalf("seed email + attachment: %v", err)
	}
	t.Cleanup(func() {
		// ON DELETE CASCADE drops the email_attachments link with the email.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM emails WHERE internal_id = $1 AND fetched_at = $2`, internalID, fetchedAt)
	})

	// (1) Real internal_id ⇒ exactly one row updated.
	affected, err := s.UpdateEmailAttachmentScore(ctx, EmailAttachmentScore{
		OrgID:        orgID,
		InternalID:   internalID,
		FetchedAt:    fetchedAt,
		AttachmentID: attachmentID,
		RiskScore:    77,
	})
	if err != nil {
		t.Fatalf("update on internal_id: %v", err)
	}
	if affected != 1 {
		t.Fatalf("update keyed on internal_id affected %d rows, want 1", affected)
	}

	// (2) Logical svc-01-style email_id (large nanosecond-derived id that never
	// equals the small BIGSERIAL) ⇒ zero rows. This is exactly what the old
	// internalIDOf() passed, demonstrating why the write-back no-oped.
	logicalEmailID := internalID + 1_700_000_000_000_000
	affected, err = s.UpdateEmailAttachmentScore(ctx, EmailAttachmentScore{
		OrgID:        orgID,
		InternalID:   logicalEmailID,
		FetchedAt:    fetchedAt,
		AttachmentID: attachmentID,
		RiskScore:    77,
	})
	if err != nil {
		t.Fatalf("update on logical email_id: %v", err)
	}
	if affected != 0 {
		t.Fatalf("update keyed on logical email_id affected %d rows, want 0", affected)
	}
}

// TestRepoStore_CacheVT_EmptyRawPersists is the regression guard for S2: a VT 404
// negative-cache write carries no body (Result.NotFound ⇒ Raw=nil). enrichment_
// results.raw_response is JSONB NOT NULL, and pgx encodes a nil []byte as SQL NULL,
// so without coercing the empty body to the JSON null literal the INSERT violates
// NOT NULL, the error is swallowed, and the negative cache never persists — every
// unknown hash then re-hits the VT API on each redelivery. DB-integration test.
func TestRepoStore_CacheVT_EmptyRawPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test in -short mode")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for store integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	s := NewRepoStore(pool)
	const orgID = int64(1)
	sha := "0000000000000000000000000000000000000000000000000000000000000516"

	var libID int64
	err = repository.WithOrgTx(ctx, pool, orgID, func(q *dbsqlc.Queries) error {
		id, qerr := q.UpsertParsedAttachment(ctx, dbsqlc.UpsertParsedAttachmentParams{Sha256: sha})
		if qerr != nil {
			return qerr
		}
		libID = id
		return nil
	})
	if err != nil {
		t.Fatalf("seed attachment_library: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM enrichment_results WHERE entity_id=$1 AND provider='virustotal'`, libID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM attachment_library WHERE sha256=$1`, sha)
	})

	// Empty Raw (the 404 negative-cache shape) must still persist.
	if err := s.CacheVT(ctx, orgID, libID, time.Now().UTC(), VTCacheInput{}, time.Hour); err != nil {
		t.Fatalf("cache vt with empty raw: %v", err)
	}
	cached, err := s.GetFreshVT(ctx, orgID, libID)
	if err != nil {
		t.Fatalf("read vt cache: %v", err)
	}
	if !cached.Found {
		t.Fatal("empty-raw VT negative-cache row did not persist (S2 regression)")
	}
	if cached.MaliciousVotes != 0 {
		t.Fatalf("negative cache should carry 0 malicious votes, got %d", cached.MaliciousVotes)
	}
}

// TestRepoStore_UpdateEmailAttachmentScore_ZeroWritesZeroNotNull is the regression
// guard for S3: a benign attachment scores 0, and the UPDATE SETs risk_score
// unconditionally (no COALESCE), so 0 must persist as a valid 0 ("scored, benign")
// — pgconv.Int4OrNull(0) would write SQL NULL ("never scored") and lose the
// verdict. DB-integration test.
func TestRepoStore_UpdateEmailAttachmentScore_ZeroWritesZeroNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB-integration test in -short mode")
	}
	dsn := os.Getenv("APP_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APP_DATABASE_URL to the non-bypass app role DSN for store integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	s := NewRepoStore(pool)
	const orgID = int64(1)
	fetchedAt := time.Now().UTC()
	ts := pgtype.Timestamptz{Time: fetchedAt, Valid: true}
	sha := "0000000000000000000000000000000000000000000000000000000000000517"

	var internalID, attachmentID int64
	err = repository.WithOrgTx(ctx, pool, orgID, func(q *dbsqlc.Queries) error {
		row, qerr := q.InsertEmail(ctx, dbsqlc.InsertEmailParams{
			FetchedAt: ts,
			OrgID:     pgtype.Int8{Int64: orgID, Valid: true},
			MessageID: pgtype.Text{String: "<p2.1-zero-score-test@cybersiren>", Valid: true},
		})
		if qerr != nil {
			return qerr
		}
		internalID = row.InternalID
		id, qerr := q.UpsertParsedAttachment(ctx, dbsqlc.UpsertParsedAttachmentParams{Sha256: sha})
		if qerr != nil {
			return qerr
		}
		attachmentID = id
		return q.InsertEmailAttachment(ctx, dbsqlc.InsertEmailAttachmentParams{
			EmailID:        internalID,
			EmailFetchedAt: ts,
			AttachmentID:   attachmentID,
			Filename:       pgtype.Text{String: "benign.pdf", Valid: true},
			OrgID:          pgtype.Int8{Int64: orgID, Valid: true},
		})
	})
	if err != nil {
		t.Fatalf("seed email + attachment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM emails WHERE internal_id = $1 AND fetched_at = $2`, internalID, fetchedAt)
		_, _ = pool.Exec(context.Background(), `DELETE FROM attachment_library WHERE sha256=$1`, sha)
	})

	affected, err := s.UpdateEmailAttachmentScore(ctx, EmailAttachmentScore{
		OrgID:        orgID,
		InternalID:   internalID,
		FetchedAt:    fetchedAt,
		AttachmentID: attachmentID,
		RiskScore:    0,
	})
	if err != nil {
		t.Fatalf("update with score 0: %v", err)
	}
	if affected != 1 {
		t.Fatalf("score-0 update affected %d rows, want 1", affected)
	}

	var rs pgtype.Int4
	err = repository.WithOrgTx(ctx, pool, orgID, func(q *dbsqlc.Queries) error {
		rows, qerr := q.ListEmailAttachments(ctx, dbsqlc.ListEmailAttachmentsParams{EmailID: internalID, EmailFetchedAt: ts})
		if qerr != nil {
			return qerr
		}
		for _, r := range rows {
			if r.AttachmentID == attachmentID {
				rs = r.RiskScore
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read back risk_score: %v", err)
	}
	if !rs.Valid {
		t.Fatal("risk_score is NULL after writing score 0 (S3 regression) — want a valid 0")
	}
	if rs.Int32 != 0 {
		t.Fatalf("risk_score = %d, want 0", rs.Int32)
	}
}
