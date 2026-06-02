package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/analyzer"
	"github.com/saif/cybersiren/shared/config"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// TestScoreAttachmentEndToEnd seeds an email + a malicious attachment_library
// row + an email_attachments occurrence, then drives scoreAttachment and
// asserts the sha256 lookup, the malicious short-circuit (score 90), and the
// risk_score writeback. Skipped in -short / no-DB; runs in CI Integration.
func TestScoreAttachmentEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DB integration test in -short mode")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("config load failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DB.DSN())
	if err != nil {
		t.Skipf("no DB pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}

	uniq := time.Now().UnixNano()
	emailID := uniq
	fetchedAt := time.Now().UTC()
	sha := fmt.Sprintf("%064x", uniq) // 64-hex sha256-shaped, unique per run

	if _, err := pool.Exec(ctx, `INSERT INTO emails (internal_id, fetched_at) VALUES ($1,$2)`, emailID, fetchedAt); err != nil {
		t.Fatalf("seed email: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM emails WHERE internal_id=$1`, emailID) //nolint:errcheck

	var attachmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO attachment_library (sha256, is_malicious, entropy, actual_extension, size_bytes)
		 VALUES ($1, TRUE, 7.9, 'exe', 1024) RETURNING id`, sha).Scan(&attachmentID); err != nil {
		t.Fatalf("seed attachment_library: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM attachment_library WHERE id=$1`, attachmentID) //nolint:errcheck

	if _, err := pool.Exec(ctx,
		`INSERT INTO email_attachments (email_id, email_fetched_at, attachment_id, filename)
		 VALUES ($1,$2,$3,'invoice.pdf')`, emailID, fetchedAt, attachmentID); err != nil {
		t.Fatalf("seed email_attachment: %v", err)
	}

	dbPool = pool
	metrics = analyzer.NewMetrics(nil)

	meta := contracts.MessageMeta{EmailID: emailID}
	att := contracts.Attachment{Filename: "invoice.pdf", ContentType: "application/pdf", SHA256: sha}
	res := scoreAttachment(ctx, meta, fetchedAt, att, zerolog.Nop())

	if !res.Malicious || res.Score != 90 {
		t.Fatalf("result = %+v, want malicious score 90", res)
	}

	var risk int
	if err := pool.QueryRow(ctx,
		`SELECT risk_score FROM email_attachments WHERE email_id=$1 AND email_fetched_at=$2 AND attachment_id=$3`,
		emailID, fetchedAt, attachmentID).Scan(&risk); err != nil {
		t.Fatalf("read risk_score: %v", err)
	}
	if risk != 90 {
		t.Errorf("email_attachments.risk_score = %d, want 90", risk)
	}
}
