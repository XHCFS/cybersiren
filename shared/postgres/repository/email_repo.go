package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/pgconv"
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
	Email db.InsertEmailParams
	// MessageID is the email's RFC 5322 Message-ID (angle brackets stripped),
	// threaded in so PersistParsed can deduplicate via the email_identities
	// registry (migration 015). Empty means the message carries no usable
	// Message-ID — such emails are intentionally NOT registered and are inserted
	// without cross-partition dedup (the registry excludes NULL message_ids).
	MessageID string
	// EmailID is the logical UUIDv7 email_id (G5/G17) assigned by svc-01 and
	// carried on the wire. It is stamped onto the email_identities row at
	// registration (migration 035) so a holder of only the opaque email_id can
	// later resolve the canonical (internal_id, fetched_at) partition key (the
	// svc-01 demo-UI /verdict read). Empty / invalid maps to a NULL column; such
	// rows are simply not resolvable by email_id.
	EmailID     string
	URLs        []ParsedURL
	Attachments []ParsedAttachment
	Recipients  []ChildRecipient
}

// persistQueries is the subset of generated db.Queries methods PersistParsed's
// transactional body uses. Narrowing to an interface keeps the idempotency
// decision logic unit-testable with a fake registry, independent of a live DB
// (the cross-org / RLS proof lives in rls_integration_test.go). *db.Queries
// satisfies it.
type persistQueries interface {
	InsertEmail(ctx context.Context, arg db.InsertEmailParams) (db.InsertEmailRow, error)
	GetEmailIdentity(ctx context.Context, arg db.GetEmailIdentityParams) (db.GetEmailIdentityRow, error)
	RegisterEmailIdentity(ctx context.Context, arg db.RegisterEmailIdentityParams) (int64, error)
	DeleteEmailByKey(ctx context.Context, arg db.DeleteEmailByKeyParams) error
	UpsertBareEnrichedThreat(ctx context.Context, arg db.UpsertBareEnrichedThreatParams) (int64, error)
	InsertEmailURL(ctx context.Context, arg db.InsertEmailURLParams) (int64, error)
	UpsertParsedAttachment(ctx context.Context, arg db.UpsertParsedAttachmentParams) (int64, error)
	InsertEmailAttachment(ctx context.Context, arg db.InsertEmailAttachmentParams) error
	InsertEmailRecipient(ctx context.Context, arg db.InsertEmailRecipientParams) (int64, error)
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
		k, err := persistParsedTx(ctx, q, orgID, in)
		if err != nil {
			return err
		}
		key = k
		return nil
	})
	if err != nil {
		return EmailKey{}, err
	}
	return key, nil
}

// persistParsedTx runs the idempotent persist inside an already-open
// org-scoped transaction (q). It dedups on the email_identities registry
// (migration 015) so a Kafka redelivery — a re-publish after the first tx
// committed — never inserts a second emails row, and a lost claim race never
// orphans one:
//
//   - No message_id: insert email + children unconditionally (NULL message_ids
//     are not registered; the registry cannot dedup them).
//   - message_id present, already registered: return the canonical
//     (internal_id, fetched_at) and SKIP every insert (idempotent re-publish).
//   - message_id present, not yet registered: insert the candidate email, then
//     claim it in email_identities. Won → insert children, return the candidate.
//     Lost the claim to a racing ingestion → delete the orphan emails row and
//     return the winner the race registered, SKIPping children.
func persistParsedTx(ctx context.Context, q persistQueries, orgID int64, in PersistParsedFull) (EmailKey, error) {
	if in.MessageID == "" {
		key, err := insertEmailRow(ctx, q, in.Email)
		if err != nil {
			return EmailKey{}, err
		}
		if err := insertEmailChildren(ctx, q, orgID, key, in); err != nil {
			return EmailKey{}, err
		}
		return key, nil
	}

	// Already persisted by a prior ingestion of the same message: return its key
	// and skip all inserts (idempotent re-publish).
	existing, err := q.GetEmailIdentity(ctx, db.GetEmailIdentityParams{OrgID: orgID, MessageID: in.MessageID})
	if err == nil {
		return EmailKey{InternalID: existing.InternalID, FetchedAt: existing.FetchedAt}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return EmailKey{}, fmt.Errorf("get email identity: %w", err)
	}

	// First sighting (so far): insert the candidate email, then try to claim it.
	key, err := insertEmailRow(ctx, q, in.Email)
	if err != nil {
		return EmailKey{}, err
	}
	// The returned id is our own key.InternalID on success (we sent it), so it is
	// discarded — ErrNoRows vs nil is the only signal that matters here.
	_, err = q.RegisterEmailIdentity(ctx, db.RegisterEmailIdentityParams{
		OrgID:      orgID,
		MessageID:  in.MessageID,
		InternalID: key.InternalID,
		FetchedAt:  key.FetchedAt,
		EmailID:    pgconv.UUIDOrNull(in.EmailID),
	})
	switch {
	case err == nil:
		// Won the claim: persist the children under the candidate key.
		if err := insertEmailChildren(ctx, q, orgID, key, in); err != nil {
			return EmailKey{}, err
		}
		return key, nil
	case errors.Is(err, pgx.ErrNoRows):
		// A racing ingestion claimed this message between our GetEmailIdentity
		// miss and our RegisterEmailIdentity. Drop the orphan email we just
		// inserted and return the winner's key, skipping children.
		if delErr := q.DeleteEmailByKey(ctx, db.DeleteEmailByKeyParams{
			InternalID: key.InternalID,
			FetchedAt:  key.FetchedAt,
		}); delErr != nil {
			return EmailKey{}, fmt.Errorf("delete orphan email after lost claim: %w", delErr)
		}
		winner, getErr := q.GetEmailIdentity(ctx, db.GetEmailIdentityParams{OrgID: orgID, MessageID: in.MessageID})
		if getErr != nil {
			return EmailKey{}, fmt.Errorf("get email identity after lost claim: %w", getErr)
		}
		return EmailKey{InternalID: winner.InternalID, FetchedAt: winner.FetchedAt}, nil
	default:
		return EmailKey{}, fmt.Errorf("register email identity: %w", err)
	}
}

// insertEmailRow inserts the emails row and returns its DB-assigned composite
// partition key.
func insertEmailRow(ctx context.Context, q persistQueries, params db.InsertEmailParams) (EmailKey, error) {
	row, err := q.InsertEmail(ctx, params)
	if err != nil {
		return EmailKey{}, fmt.Errorf("insert email: %w", err)
	}
	return EmailKey{InternalID: row.InternalID, FetchedAt: row.FetchedAt}, nil
}

// insertEmailChildren writes the URL / attachment / recipient child rows under
// the email's partition key, resolving the enriched_threats / attachment_library
// parent FKs inside the same transaction.
func insertEmailChildren(ctx context.Context, q persistQueries, orgID int64, key EmailKey, in PersistParsedFull) error {
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
}
