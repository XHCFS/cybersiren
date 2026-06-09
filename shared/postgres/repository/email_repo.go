package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// EmailRepository persists a parsed email and all of its child artefacts
// (URLs, attachments, recipients) inside one tenant-scoped transaction.
//
// G5/G17 two-id model: InsertEmail lets the DB assign internal_id (BIGSERIAL)
// and returns the (internal_id, fetched_at) partition key. The logical email_id
// is carried separately by the caller — this repo never assumes
// internal_id == email_id.
type EmailRepository struct {
	pool *pgxpool.Pool
}

// NewEmailRepository constructs an EmailRepository over the given pool.
func NewEmailRepository(pool *pgxpool.Pool) *EmailRepository {
	return &EmailRepository{pool: pool}
}

// EmailKey is the composite partition key of the partitioned emails table.
type EmailKey struct {
	InternalID int64
	FetchedAt  pgtype.Timestamptz
}

// ChildRecipient is one to/cc/bcc recipient of the email.
type ChildRecipient struct {
	Address       string
	DisplayName   pgtype.Text
	RecipientType string
}

// ParsedURL is one extracted URL the parser persists end-to-end: the bare
// enriched_threats UPSERT inputs (url/domain/tld) and the email_urls link's
// visible_text. The enriched_threats id resolved by the UPSERT becomes the
// email_urls.threat_id FK — the repo wires it up so the caller never has to
// pre-resolve threat ids.
type ParsedURL struct {
	URL         string
	Domain      pgtype.Text
	TLD         pgtype.Text
	VisibleText pgtype.Text
}

// ParsedAttachment is one attachment the parser persists end-to-end: the
// attachment_library UPSERT content fields (keyed on sha256) plus the
// email_attachments link columns. The attachment_library id resolved by the
// UPSERT becomes the email_attachments.attachment_id FK.
type ParsedAttachment struct {
	// Library is the content-derived attachment_library row (sha256 + md5 +
	// sha1 + actual_extension + size_bytes + entropy + storage_uri). storage_uri
	// is set by the caller after the binary is uploaded to object storage (G6).
	Library db.UpsertParsedAttachmentParams
	// Link columns on email_attachments.
	Filename    pgtype.Text
	ContentType pgtype.Text
	ContentID   pgtype.Text
	Disposition pgtype.Text
}

// PersistParsedFull bundles the full SVC-02 parser output so the 6 write-groups
// (emails, enriched_threats, email_urls, attachment_library, email_attachments,
// email_recipients) execute atomically under one org GUC. The URL/attachment
// children carry their parent-table inputs (enriched_threats /
// attachment_library) so the repo resolves the FKs itself inside the same
// transaction.
type PersistParsedFull struct {
	Email       db.InsertEmailParams
	URLs        []ParsedURL
	Attachments []ParsedAttachment
	Recipients  []ChildRecipient
}

// PersistParsed writes the email and every child artefact across all six SVC-02
// write-groups in a single org-scoped transaction (ARCH-SPEC §14 step 2):
//
//	emails INSERT (RETURNING the DB-assigned internal_id, fetched_at) →
//	per URL: enriched_threats bare UPSERT → email_urls INSERT (threat_id FK) →
//	per attachment: attachment_library UPSERT → email_attachments INSERT →
//	per recipient: email_recipients INSERT.
//
// The whole batch shares one SET LOCAL app.current_org_id (G10), so a partial
// failure rolls back atomically and no row escapes the tenant boundary. orgID
// must match in.Email.OrgID. Returns the DB-assigned composite key so the caller
// can carry (internal_id, fetched_at) downstream alongside the logical email_id
// (G5/G17 two-id model — no internal_id == email_id invariant).
func (r *EmailRepository) PersistParsed(ctx context.Context, orgID int64, in PersistParsedFull) (EmailKey, error) {
	if r == nil || r.pool == nil {
		return EmailKey{}, errors.New("email repository: nil pool")
	}

	var key EmailKey
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		row, err := q.InsertEmail(ctx, in.Email)
		if err != nil {
			return fmt.Errorf("insert email: %w", err)
		}
		key = EmailKey{InternalID: row.InternalID, FetchedAt: row.FetchedAt}
		orgParam := pgtype.Int8{Int64: orgID, Valid: true}

		for i, u := range in.URLs {
			threatID, err := q.UpsertBareEnrichedThreat(ctx, db.UpsertBareEnrichedThreatParams{
				Url:    u.URL,
				Domain: u.Domain,
				Tld:    u.TLD,
				OrgID:  orgParam,
			})
			if err != nil {
				return fmt.Errorf("upsert bare enriched_threat[%d]: %w", i, err)
			}
			if _, err := q.InsertEmailURL(ctx, db.InsertEmailURLParams{
				EmailID:        key.InternalID,
				EmailFetchedAt: key.FetchedAt,
				ThreatID:       pgtype.Int8{Int64: threatID, Valid: true},
				VisibleText:    u.VisibleText,
				OrgID:          orgParam,
			}); err != nil {
				return fmt.Errorf("insert email_url[%d]: %w", i, err)
			}
		}

		for i, a := range in.Attachments {
			attachmentID, err := q.UpsertParsedAttachment(ctx, a.Library)
			if err != nil {
				return fmt.Errorf("upsert attachment_library[%d]: %w", i, err)
			}
			if err := q.InsertEmailAttachment(ctx, db.InsertEmailAttachmentParams{
				EmailID:        key.InternalID,
				EmailFetchedAt: key.FetchedAt,
				AttachmentID:   attachmentID,
				Filename:       a.Filename,
				ContentType:    a.ContentType,
				ContentID:      a.ContentID,
				Disposition:    a.Disposition,
				OrgID:          orgParam,
			}); err != nil {
				return fmt.Errorf("insert email_attachment[%d]: %w", i, err)
			}
		}

		for i, rc := range in.Recipients {
			if _, err := q.InsertEmailRecipient(ctx, db.InsertEmailRecipientParams{
				EmailID:        key.InternalID,
				EmailFetchedAt: key.FetchedAt,
				OrgID:          orgParam,
				Address:        rc.Address,
				DisplayName:    rc.DisplayName,
				RecipientType:  rc.RecipientType,
			}); err != nil {
				return fmt.Errorf("insert email_recipient[%d]: %w", i, err)
			}
		}
		return nil
	})
	if err != nil {
		return EmailKey{}, err
	}
	return key, nil
}
