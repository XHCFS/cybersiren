package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// ErrNoPriorEnrichment is returned by GetPriorEnrichedThreat when this org has
// no previously-enriched row for the domain. It is a normal "cache miss", not a
// failure — callers fall through to live enrichment.
var ErrNoPriorEnrichment = errors.New("enrichment repository: no prior enriched threat for domain")

// EnrichmentRepository owns the enrichment cache (enrichment_results) and the
// async enrichment work queue (enrichment_jobs). Both tables are RLS-forced, so
// writes go through an org-scoped transaction.
type EnrichmentRepository struct {
	pool *pgxpool.Pool
}

// NewEnrichmentRepository constructs an EnrichmentRepository over the pool.
func NewEnrichmentRepository(pool *pgxpool.Pool) *EnrichmentRepository {
	return &EnrichmentRepository{pool: pool}
}

// UpsertResult caches a provider's enrichment for an entity (refreshing the
// payload and TTL on re-fetch) and returns the row id. Runs in an org-scoped tx.
func (r *EnrichmentRepository) UpsertResult(ctx context.Context, orgID int64, p db.UpsertEnrichmentResultParams) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, errors.New("enrichment repository: nil pool")
	}
	var id int64
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.UpsertEnrichmentResult(ctx, p)
		if err != nil {
			return fmt.Errorf("upsert enrichment_result: %w", err)
		}
		id = got
		return nil
	})
	return id, err
}

// EnqueueJob enqueues a pending enrichment job and returns its id. Runs in an
// org-scoped tx.
func (r *EnrichmentRepository) EnqueueJob(ctx context.Context, orgID int64, p db.EnqueueEnrichmentJobParams) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, errors.New("enrichment repository: nil pool")
	}
	var id int64
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.EnqueueEnrichmentJob(ctx, p)
		if err != nil {
			return fmt.Errorf("enqueue enrichment_job: %w", err)
		}
		id = got
		return nil
	})
	return id, err
}

// CompleteJob marks a claimed job completed under the owning org's GUC.
func (r *EnrichmentRepository) CompleteJob(ctx context.Context, orgID, jobID int64) error {
	if r == nil || r.pool == nil {
		return errors.New("enrichment repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.CompleteEnrichmentJob(ctx, jobID); err != nil {
			return fmt.Errorf("complete enrichment_job %d: %w", jobID, err)
		}
		return nil
	})
}

// FailJob records a failure (and retries while attempts remain) under the
// owning org's GUC.
func (r *EnrichmentRepository) FailJob(ctx context.Context, orgID, jobID int64, lastError string) error {
	if r == nil || r.pool == nil {
		return errors.New("enrichment repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.FailEnrichmentJob(ctx, db.FailEnrichmentJobParams{
			ID:        jobID,
			LastError: pgtype.Text{String: lastError, Valid: lastError != ""},
		}); err != nil {
			return fmt.Errorf("fail enrichment_job %d: %w", jobID, err)
		}
		return nil
	})
}

// ── SVC-03 URL-enrichment persistence (ARCH-SPEC §14 step 3a) ────────────────
//
// SVC-03 consumes analysis.urls (only email_id/org_id/fetched_at on the
// envelope), so before it can UPDATE enriched_threats or audit a TI match it
// must resolve the email_urls rows SVC-02 already persisted for the email. The
// methods below give SVC-03 a cohesive enrichment-persistence surface — the
// prior-email READ, the email_urls lookup, the enriched_threats UPDATE, and the
// email_url_ti_matches INSERT — without coupling it to SVC-02's URLRepository.
// All run under an org-scoped tx (G10 RLS GUC).

// ListEmailURLs returns the email_urls SVC-02 persisted for one email
// (composite PK internalID + fetchedAt), so SVC-03 can map each scored URL back
// to its email_url id (for email_url_ti_matches) and threat id (for the
// enriched_threats UPDATE). RLS scopes the rows to orgID. A nil/empty result is
// not an error: it means SVC-02 has not yet persisted this email's URLs (P1.1
// lands in parallel), in which case SVC-03 fail-softs and skips the row-keyed
// writes for this message.
func (r *EnrichmentRepository) ListEmailURLs(
	ctx context.Context,
	orgID, internalID int64,
	fetchedAt pgtype.Timestamptz,
) ([]db.ListEmailURLsRow, error) {
	if r == nil || r.pool == nil {
		return nil, errors.New("enrichment repository: nil pool")
	}
	var rows []db.ListEmailURLsRow
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.ListEmailURLs(ctx, db.ListEmailURLsParams{
			EmailID:        internalID,
			EmailFetchedAt: fetchedAt,
		})
		if err != nil {
			return fmt.Errorf("list email_urls: %w", err)
		}
		rows = got
		return nil
	})
	return rows, err
}

// GetPriorEnrichedThreat returns this org's most-recently-enriched
// enriched_threats row for the given domain, excluding excludeID (the bare row
// just upserted for the current URL). It lets SVC-03 reuse prior enrichment for
// a host it has already analysed (ARCH-SPEC §14 step 3a "R enriched_threats —
// prior-email URL lookup") instead of re-running live enrichment. Returns
// ErrNoPriorEnrichment on a cache miss so callers can branch cleanly. Runs in an
// org-scoped tx (RLS).
func (r *EnrichmentRepository) GetPriorEnrichedThreat(
	ctx context.Context,
	orgID int64,
	domain string,
	excludeID int64,
) (db.EnrichedThreat, error) {
	// An empty domain can never have a prior enrichment row — short-circuit to
	// the cache-miss sentinel before touching the pool, so a URL with no parsable
	// host is a clean miss rather than a wasted transaction.
	if domain == "" {
		return db.EnrichedThreat{}, ErrNoPriorEnrichment
	}
	if r == nil || r.pool == nil {
		return db.EnrichedThreat{}, errors.New("enrichment repository: nil pool")
	}
	var out db.EnrichedThreat
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.GetPriorEnrichedThreat(ctx, db.GetPriorEnrichedThreatParams{
			Domain: pgtype.Text{String: domain, Valid: true},
			ID:     excludeID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoPriorEnrichment
		}
		if err != nil {
			return fmt.Errorf("get prior enriched_threat: %w", err)
		}
		out = got
		return nil
	})
	return out, err
}

// ApplyThreatEnrichment UPDATEs an existing enriched_threats row with SVC-03's
// enrichment output (the ~28-col COALESCE UPDATE on the bare row SVC-02
// inserted). NULL params leave their columns unchanged. p.ID is the
// enriched_threats id (the email_urls.threat_id FK). Runs in an org-scoped tx;
// the query also pins is_global = FALSE so a tenant only ever enriches its own
// rows.
func (r *EnrichmentRepository) ApplyThreatEnrichment(ctx context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error {
	if r == nil || r.pool == nil {
		return errors.New("enrichment repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.UpdateEnrichedThreatEnrichment(ctx, p); err != nil {
			return fmt.Errorf("update enriched_threat enrichment: %w", err)
		}
		return nil
	})
}

// RecordTIMatch appends a TI-feed-match audit row for an email URL
// (email_url_ti_matches, the feed-match audit trail). The query derives org_id
// from the parent email_urls row under the same GUC, so a match can only ever
// attach to a URL this org can see; a foreign/missing email_url_id inserts
// nothing. ON CONFLICT DO NOTHING keeps it idempotent. Runs in an org-scoped tx.
func (r *EnrichmentRepository) RecordTIMatch(ctx context.Context, orgID int64, p db.InsertEmailURLTIMatchParams) error {
	if r == nil || r.pool == nil {
		return errors.New("enrichment repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.InsertEmailURLTIMatch(ctx, p); err != nil {
			return fmt.Errorf("insert email_url_ti_match: %w", err)
		}
		return nil
	})
}
