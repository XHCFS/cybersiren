package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
)

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
