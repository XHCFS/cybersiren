// Package store persists a parsed email and its junction rows to Postgres in a
// single transaction. It is the write half of SVC-02: the parser produces a
// structured email, the store lands it so the rest of the pipeline (SVC-08's
// emails UPDATE, the dashboard, SVC-03's prior-email lookup) has a real row.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
)

// EmailRecord is the flat header/body projection of one email, ready to be
// inserted into the partitioned emails table. InternalID and FetchedAt form the
// partition key and must match the values SVC-02 carries on the Kafka envelope
// so SVC-08's later UPDATE targets this exact row.
type EmailRecord struct {
	InternalID     int64
	FetchedAt      time.Time
	OrgID          int64
	MessageID      string
	SenderName     string
	SenderEmail    string
	SenderDomain   string
	ReplyToEmail   string
	ReturnPath     string
	AuthSPF        string
	AuthDKIM       string
	AuthDMARC      string
	AuthARC        string
	MailerAgent    string
	InReplyTo      string
	ReferencesList []string
	ContentCharset string
	Precedence     string
	ListID         string
	Subject        string
	SentTimestamp  *int64
	HeadersJSON    []byte
	BodyPlain      string
	BodyHTML       string
}

// Writer persists parsed emails. It retries the whole transaction with
// exponential backoff so a transient DB failure does not acknowledge the Kafka
// offset and silently drop an email.
type Writer struct {
	pool       *pgxpool.Pool
	maxRetries int
	log        zerolog.Logger
}

// NewWriter constructs a Writer. maxRetries < 0 is clamped to 0.
func NewWriter(pool *pgxpool.Pool, maxRetries int, log zerolog.Logger) *Writer {
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &Writer{pool: pool, maxRetries: maxRetries, log: log}
}

// Persist writes the email and its junction rows in one transaction, retrying
// on transient failure. The writes run in FK-safe order: emails, then per-URL
// (enriched_threats upsert → email_urls), per-attachment (attachment_library
// upsert → email_attachments), and recipients.
func (w *Writer) Persist(
	ctx context.Context,
	rec EmailRecord,
	urls []email.ExtractedURL,
	attachments []email.ParsedAttachment,
	recipients []email.Recipient,
) error {
	if w == nil || w.pool == nil {
		return errors.New("email store: not initialised")
	}

	attempts := w.maxRetries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("persist email: %w", err)
		}

		err := w.runOnce(ctx, rec, urls, attachments, recipients)
		if err == nil {
			return nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		backoff := backoffDuration(attempt)
		w.log.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", attempts).
			Int64("email_internal_id", rec.InternalID).
			Dur("backoff", backoff).
			Msg("email persist transaction failed; retrying")

		select {
		case <-ctx.Done():
			return fmt.Errorf("persist email: %w", ctx.Err())
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("persist email after %d attempts: %w", attempts, lastErr)
}

// runOnce executes the six writes inside a single transaction. Any error rolls
// the whole email back so partial state never reaches the downstream services.
func (w *Writer) runOnce(
	ctx context.Context,
	rec EmailRecord,
	urls []email.ExtractedURL,
	attachments []email.ParsedAttachment,
	recipients []email.Recipient,
) error {
	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin email tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := dbsqlc.New(tx)

	inserted, err := q.InsertEmail(ctx, buildInsertEmailParams(rec))
	if err != nil {
		return fmt.Errorf("insert email (internal_id=%d): %w", rec.InternalID, err)
	}
	if inserted == 0 {
		// Redelivery of an already-persisted email: the junction rows were
		// written on the first delivery, so committing the no-op insert keeps
		// the handler idempotent without duplicating children.
		w.log.Debug().Int64("email_internal_id", rec.InternalID).Msg("email already persisted; skipping junction writes")
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit email tx: %w", err)
		}
		return nil
	}

	for _, u := range urls {
		threatID, err := q.UpsertEnrichedThreatBare(ctx, buildThreatParams(u.URL))
		if err != nil {
			return fmt.Errorf("upsert enriched_threat (%q): %w", u.URL, err)
		}
		if err := q.InsertEmailURL(ctx, buildEmailURLParams(rec, threatID, u.VisibleText)); err != nil {
			return fmt.Errorf("insert email_url (threat_id=%d): %w", threatID, err)
		}
	}

	for _, a := range attachments {
		attachmentID, err := q.UpsertAttachmentLibrary(ctx, buildAttachmentParams(a))
		if err != nil {
			return fmt.Errorf("upsert attachment_library (sha256=%s): %w", a.SHA256, err)
		}
		if err := q.InsertEmailAttachment(ctx, buildEmailAttachmentParams(rec, attachmentID, a)); err != nil {
			return fmt.Errorf("insert email_attachment (attachment_id=%d): %w", attachmentID, err)
		}
	}

	for _, r := range recipients {
		if err := q.InsertEmailRecipient(ctx, buildRecipientParams(rec, r)); err != nil {
			return fmt.Errorf("insert email_recipient (%q): %w", r.Address, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit email tx: %w", err)
	}
	return nil
}

// ── parameter builders (pure, unit-tested) ───────────────────────────────────

func buildInsertEmailParams(rec EmailRecord) dbsqlc.InsertEmailParams {
	return dbsqlc.InsertEmailParams{
		InternalID:     rec.InternalID,
		FetchedAt:      pgtype.Timestamptz{Time: rec.FetchedAt, Valid: !rec.FetchedAt.IsZero()},
		OrgID:          int8OrNull(rec.OrgID),
		MessageID:      textOrNull(rec.MessageID),
		SenderName:     textOrNull(rec.SenderName),
		SenderEmail:    textOrNull(rec.SenderEmail),
		SenderDomain:   textOrNull(rec.SenderDomain),
		ReplyToEmail:   textOrNull(rec.ReplyToEmail),
		ReturnPath:     textOrNull(rec.ReturnPath),
		AuthSpf:        textOrNull(rec.AuthSPF),
		AuthDkim:       textOrNull(rec.AuthDKIM),
		AuthDmarc:      textOrNull(rec.AuthDMARC),
		AuthArc:        textOrNull(rec.AuthARC),
		MailerAgent:    textOrNull(rec.MailerAgent),
		InReplyTo:      textOrNull(rec.InReplyTo),
		ReferencesList: rec.ReferencesList,
		ContentCharset: textOrNull(rec.ContentCharset),
		Precedence:     textOrNull(rec.Precedence),
		ListID:         textOrNull(rec.ListID),
		Subject:        textOrNull(rec.Subject),
		SentTimestamp:  int8PtrOrNull(rec.SentTimestamp),
		HeadersJson:    rec.HeadersJSON,
		BodyPlain:      textOrNull(rec.BodyPlain),
		BodyHtml:       textOrNull(rec.BodyHTML),
	}
}

func buildThreatParams(rawURL string) dbsqlc.UpsertEnrichedThreatBareParams {
	domain, tld := hostAndTLD(rawURL)
	return dbsqlc.UpsertEnrichedThreatBareParams{
		Url:    rawURL,
		Domain: textOrNull(domain),
		Tld:    textOrNull(tld),
	}
}

func buildEmailURLParams(rec EmailRecord, threatID int64, visibleText string) dbsqlc.InsertEmailURLParams {
	return dbsqlc.InsertEmailURLParams{
		EmailID:        rec.InternalID,
		EmailFetchedAt: pgtype.Timestamptz{Time: rec.FetchedAt, Valid: !rec.FetchedAt.IsZero()},
		ThreatID:       pgtype.Int8{Int64: threatID, Valid: true},
		VisibleText:    textOrNull(visibleText),
		OrgID:          int8OrNull(rec.OrgID),
	}
}

func buildAttachmentParams(a email.ParsedAttachment) dbsqlc.UpsertAttachmentLibraryParams {
	return dbsqlc.UpsertAttachmentLibraryParams{
		Sha256:          a.SHA256,
		Md5:             textOrNull(a.MD5),
		Sha1:            textOrNull(a.SHA1),
		SizeBytes:       pgtype.Int8{Int64: a.SizeBytes, Valid: true},
		Entropy:         pgtype.Float8{Float64: a.Entropy, Valid: true},
		ActualExtension: textOrNull(a.ActualExtension),
	}
}

func buildEmailAttachmentParams(rec EmailRecord, attachmentID int64, a email.ParsedAttachment) dbsqlc.InsertEmailAttachmentParams {
	return dbsqlc.InsertEmailAttachmentParams{
		EmailID:        rec.InternalID,
		EmailFetchedAt: pgtype.Timestamptz{Time: rec.FetchedAt, Valid: !rec.FetchedAt.IsZero()},
		AttachmentID:   attachmentID,
		Filename:       textOrNull(a.Filename),
		ContentType:    textOrNull(a.ContentType),
		ContentID:      textOrNull(a.ContentID),
		Disposition:    textOrNull(a.Disposition),
		OrgID:          int8OrNull(rec.OrgID),
	}
}

func buildRecipientParams(rec EmailRecord, r email.Recipient) dbsqlc.InsertEmailRecipientParams {
	return dbsqlc.InsertEmailRecipientParams{
		EmailID:        rec.InternalID,
		EmailFetchedAt: pgtype.Timestamptz{Time: rec.FetchedAt, Valid: !rec.FetchedAt.IsZero()},
		OrgID:          int8OrNull(rec.OrgID),
		Address:        r.Address,
		DisplayName:    textOrNull(r.DisplayName),
		RecipientType:  r.Type,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// hostAndTLD extracts the lowercase host and its top-level label from a URL.
// It is a best-effort split for the bare enriched_threats row; SVC-03's
// enrichment later refines domain/TLD with a public-suffix-aware parse.
func hostAndTLD(rawURL string) (host, tld string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	if i := strings.LastIndex(host, "."); i >= 0 && i < len(host)-1 {
		tld = host[i+1:]
	}
	return host, tld
}

// textOrNull maps an empty string to SQL NULL and any other value to a valid
// text, so absent header fields are stored as NULL rather than "".
func textOrNull(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// int8OrNull maps a zero id to SQL NULL (no owning org) and any positive value
// to a valid int8.
func int8OrNull(v int64) pgtype.Int8 {
	return pgtype.Int8{Int64: v, Valid: v != 0}
}

// int8PtrOrNull maps a nil pointer to SQL NULL and a non-nil pointer to its
// value, preserving the NULL-vs-zero distinction sent_timestamp requires.
func int8PtrOrNull(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}

// backoffDuration returns an exponential backoff capped at 5s.
func backoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > 5*time.Second {
			return 5 * time.Second
		}
	}
	return d
}
