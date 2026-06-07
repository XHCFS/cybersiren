package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

// URLRepository owns enriched_threats and the email-URL TI match audit trail.
// enriched_threats has a two-phase lifecycle: SVC-02 UPSERTs a bare row (taking
// its id as the email_urls.threat_id FK); SVC-03/04 later UPDATE it in place
// with enrichment. enriched_threats is RLS-forced (with a global-row carve-out),
// so writes go through an org-scoped transaction.
type URLRepository struct {
	pool *pgxpool.Pool
}

// NewURLRepository constructs a URLRepository over the given pool.
func NewURLRepository(pool *pgxpool.Pool) *URLRepository {
	return &URLRepository{pool: pool}
}

// UpsertBareThreat idempotently inserts (or refreshes last_seen on) a bare
// enriched_threats row for url/domain/tld and returns its id, used as the
// email_urls.threat_id FK. Runs in an org-scoped tx.
func (r *URLRepository) UpsertBareThreat(ctx context.Context, orgID int64, p db.UpsertBareEnrichedThreatParams) (int64, error) {
	if r == nil || r.pool == nil {
		return 0, errors.New("url repository: nil pool")
	}
	var id int64
	err := WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		got, err := q.UpsertBareEnrichedThreat(ctx, p)
		if err != nil {
			return fmt.Errorf("upsert bare enriched_threat: %w", err)
		}
		id = got
		return nil
	})
	return id, err
}

// ApplyEnrichment updates an existing enriched_threats row with enrichment
// output. NULL fields in p leave the corresponding columns unchanged. Runs in
// an org-scoped tx.
func (r *URLRepository) ApplyEnrichment(ctx context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error {
	if r == nil || r.pool == nil {
		return errors.New("url repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.UpdateEnrichedThreatEnrichment(ctx, p); err != nil {
			return fmt.Errorf("update enriched_threat enrichment: %w", err)
		}
		return nil
	})
}

// RecordTIMatch appends a TI-match audit row for an email URL. The row inherits
// tenant isolation from its parent email_urls row, so it is written under the
// same org GUC as the rest of the URL graph.
func (r *URLRepository) RecordTIMatch(ctx context.Context, orgID int64, p db.InsertEmailURLTIMatchParams) error {
	if r == nil || r.pool == nil {
		return errors.New("url repository: nil pool")
	}
	return WithOrgTx(ctx, r.pool, orgID, func(q *db.Queries) error {
		if err := q.InsertEmailURLTIMatch(ctx, p); err != nil {
			return fmt.Errorf("insert email_url_ti_match: %w", err)
		}
		return nil
	})
}
