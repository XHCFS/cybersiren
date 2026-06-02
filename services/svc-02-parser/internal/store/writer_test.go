package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	"github.com/saif/cybersiren/shared/config"
)

func TestBuildInsertEmailParams(t *testing.T) {
	t.Parallel()

	fetchedAt := time.Now().UTC().Truncate(time.Second)
	ts := int64(1700000000)
	rec := EmailRecord{
		InternalID:    42,
		FetchedAt:     fetchedAt,
		OrgID:         7,
		SenderEmail:   "alice@example.com",
		Subject:       "hi",
		SentTimestamp: &ts,
		BodyPlain:     "body",
		MailerAgent:   "", // empty → NULL
	}

	p := buildInsertEmailParams(rec)
	if p.InternalID != 42 {
		t.Errorf("InternalID = %d, want 42", p.InternalID)
	}
	if !p.FetchedAt.Valid || !p.FetchedAt.Time.Equal(fetchedAt) {
		t.Errorf("FetchedAt = %v valid=%v, want %v", p.FetchedAt.Time, p.FetchedAt.Valid, fetchedAt)
	}
	if !p.OrgID.Valid || p.OrgID.Int64 != 7 {
		t.Errorf("OrgID = %v, want valid 7", p.OrgID)
	}
	if !p.SentTimestamp.Valid || p.SentTimestamp.Int64 != ts {
		t.Errorf("SentTimestamp = %v, want valid %d", p.SentTimestamp, ts)
	}
	if p.MailerAgent.Valid {
		t.Errorf("empty MailerAgent should map to NULL, got %v", p.MailerAgent)
	}
}

func TestNullMappingForUnsetIDsAndTimestamp(t *testing.T) {
	t.Parallel()

	rec := EmailRecord{InternalID: 1} // OrgID 0, SentTimestamp nil
	p := buildInsertEmailParams(rec)
	if p.OrgID.Valid {
		t.Errorf("OrgID 0 should map to NULL, got %v", p.OrgID)
	}
	if p.SentTimestamp.Valid {
		t.Errorf("nil SentTimestamp should map to NULL, got %v", p.SentTimestamp)
	}
}

func TestHostAndTLD(t *testing.T) {
	t.Parallel()

	cases := []struct {
		url, host, tld string
	}{
		{"https://login.Example.com/reset?x=1", "login.example.com", "com"},
		{"http://10.0.0.1:8080/a", "10.0.0.1", "1"},
		{"not a url", "", ""},
		{"https://example.org", "example.org", "org"},
	}
	for _, c := range cases {
		host, tld := hostAndTLD(c.url)
		if host != c.host || tld != c.tld {
			t.Errorf("hostAndTLD(%q) = (%q,%q), want (%q,%q)", c.url, host, tld, c.host, c.tld)
		}
	}
}

func TestBuildThreatAndURLParamsLink(t *testing.T) {
	t.Parallel()

	rec := EmailRecord{InternalID: 9, FetchedAt: time.Now().UTC(), OrgID: 3}
	tp := buildThreatParams("https://x.example.com/a")
	if tp.Url != "https://x.example.com/a" || tp.Domain.String != "x.example.com" {
		t.Errorf("threat params = %+v", tp)
	}
	up := buildEmailURLParams(rec, 55, "Click Here")
	if up.EmailID != 9 || !up.ThreatID.Valid || up.ThreatID.Int64 != 55 || up.VisibleText.String != "Click Here" {
		t.Errorf("email_url params = %+v", up)
	}
}

func TestBackoffCappedAt5s(t *testing.T) {
	t.Parallel()

	if got := backoffDuration(0); got != 100*time.Millisecond {
		t.Errorf("backoff(0) = %s, want 100ms", got)
	}
	if got := backoffDuration(100); got != 5*time.Second {
		t.Errorf("backoff(100) = %s, want 5s cap", got)
	}
}

// TestPersistEndToEnd exercises the full transaction against a real Postgres.
// It is skipped in -short mode and when no DB is reachable, so it runs in the
// Integration CI job (which provisions Postgres + applies migrations) and is a
// no-op in the Build & Test job.
func TestPersistEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test in -short mode")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config load failed, skipping DB test: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DB.DSN())
	if err != nil {
		t.Skipf("no DB pool, skipping: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB not reachable, skipping: %v", err)
	}

	w := NewWriter(pool, 1, zerolog.Nop())

	// Unique partition-keyed id so reruns don't collide; fetched_at lands in
	// the current monthly partition.
	internalID := time.Now().UnixNano()
	fetchedAt := time.Now().UTC()
	rec := EmailRecord{
		InternalID:  internalID,
		FetchedAt:   fetchedAt,
		SenderEmail: "alice@example.com",
		Subject:     "integration",
		BodyPlain:   "hello",
	}
	urls := []email.ExtractedURL{{URL: "https://persist-test.example.com/a", VisibleText: "go"}}
	atts := []email.ParsedAttachment{{
		SHA256:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		MD5:       "ffffffffffffffffffffffffffffffff",
		SHA1:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes: 3, Entropy: 1.5, ActualExtension: "bin", Filename: "x.bin",
	}}
	recips := []email.Recipient{{Address: "bob@example.org", Type: "to"}}

	if err := w.Persist(ctx, rec, urls, atts, recips); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	var (
		emailCount, urlCount, attCount, recipCount int
	)
	row := pool.QueryRow(ctx, `SELECT count(*) FROM emails WHERE internal_id=$1`, internalID)
	if err := row.Scan(&emailCount); err != nil || emailCount != 1 {
		t.Fatalf("emails count = %d (err %v), want 1", emailCount, err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_urls WHERE email_id=$1`, internalID).Scan(&urlCount)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_attachments WHERE email_id=$1`, internalID).Scan(&attCount)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_recipients WHERE email_id=$1`, internalID).Scan(&recipCount)
	if urlCount != 1 || attCount != 1 || recipCount != 1 {
		t.Fatalf("junction counts urls=%d att=%d recip=%d, want 1/1/1", urlCount, attCount, recipCount)
	}

	// email_urls.threat_id must reference a real enriched_threats row.
	var fkOK bool
	_ = pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM email_urls u JOIN enriched_threats t ON t.id = u.threat_id
			WHERE u.email_id = $1
		)`, internalID).Scan(&fkOK)
	if !fkOK {
		t.Errorf("email_urls.threat_id does not reference an enriched_threats row")
	}

	// Redelivery must be idempotent: persisting the same email again leaves the
	// counts unchanged (no duplicate junction rows, no PK conflict).
	if err := w.Persist(ctx, rec, urls, atts, recips); err != nil {
		t.Fatalf("Persist (redelivery): %v", err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM email_urls WHERE email_id=$1`, internalID).Scan(&urlCount)
	if urlCount != 1 {
		t.Errorf("after redelivery email_urls = %d, want 1 (idempotent)", urlCount)
	}

	// Clean up; emails cascade covers the junction rows.
	_, _ = pool.Exec(ctx, `DELETE FROM emails WHERE internal_id=$1`, internalID)
}
