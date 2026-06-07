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

// PersistParsedEmail bundles the email row plus its child artefacts so they can
// be written atomically under one org GUC. The child rows do not carry the
// email key yet; it is filled in from the InsertEmail result before they are
// inserted.
type PersistParsedEmail struct {
	Email       db.InsertEmailParams
	URLs        []ChildURL
	Attachments []ChildAttachment
	Recipients  []ChildRecipient
}

// ChildURL is one extracted URL plus its enriched_threats linkage. ThreatID is
// resolved by the caller via UpsertBareEnrichedThreat before this is built.
type ChildURL struct {
	ThreatID    pgtype.Int8
	VisibleText pgtype.Text
}

// ChildAttachment links a parsed attachment to its attachment_library row.
type ChildAttachment struct {
	AttachmentID     int64
	Filename         pgtype.Text
	ContentType      pgtype.Text
	AnalysisMetadata []byte
	ContentID        pgtype.Text
	Disposition      pgtype.Text
	RiskScore        pgtype.Int4
}

// ChildRecipient is one to/cc/bcc recipient of the email.
type ChildRecipient struct {
	Address       string
	DisplayName   pgtype.Text
	RecipientType string
}

// Insert writes the email and all child rows in a single org-scoped tx and
// returns the DB-assigned composite key. orgID must match in.Email.OrgID.
func (r *EmailRepository) Insert(ctx context.Context, orgID int64, in PersistParsedEmail) (EmailKey, error) {
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
			if _, err := q.InsertEmailURL(ctx, db.InsertEmailURLParams{
				EmailID:        key.InternalID,
				EmailFetchedAt: key.FetchedAt,
				ThreatID:       u.ThreatID,
				VisibleText:    u.VisibleText,
				OrgID:          orgParam,
			}); err != nil {
				return fmt.Errorf("insert email_url[%d]: %w", i, err)
			}
		}

		for i, a := range in.Attachments {
			if err := q.InsertEmailAttachment(ctx, db.InsertEmailAttachmentParams{
				EmailID:          key.InternalID,
				EmailFetchedAt:   key.FetchedAt,
				AttachmentID:     a.AttachmentID,
				Filename:         a.Filename,
				ContentType:      a.ContentType,
				AnalysisMetadata: a.AnalysisMetadata,
				ContentID:        a.ContentID,
				Disposition:      a.Disposition,
				RiskScore:        a.RiskScore,
				OrgID:            orgParam,
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
