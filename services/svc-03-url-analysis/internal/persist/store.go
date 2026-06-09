package persist

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// RepoStore is the production EnrichmentStore: it composes the shared
// repository layer over a single pgx pool. Every method runs inside an
// org-scoped transaction (WithOrgTx sets app.current_org_id — G10 RLS), so the
// tenant boundary is enforced at the DB layer, not in application code.
//
// The bare-threat upsert that resolves a URL's enriched_threats id lives on the
// shared URLRepository (SVC-02's two-phase write owner); the enrichment UPDATE,
// prior-email read, TI-match audit, results cache, and job lifecycle live on the
// shared EnrichmentRepository. RepoStore wires both behind the EnrichmentStore
// interface SVC-03 persistence depends on.
type RepoStore struct {
	urls   *repository.URLRepository
	enrich *repository.EnrichmentRepository
}

// NewRepoStore builds a RepoStore over pool. Returns nil when pool is nil (the
// handler then runs without persistence, e.g. NeedsDB false in a test harness).
func NewRepoStore(pool *pgxpool.Pool) *RepoStore {
	if pool == nil {
		return nil
	}
	return &RepoStore{
		urls:   repository.NewURLRepository(pool),
		enrich: repository.NewEnrichmentRepository(pool),
	}
}

// Ensure RepoStore satisfies EnrichmentStore at compile time.
var _ EnrichmentStore = (*RepoStore)(nil)

func (s *RepoStore) ResolveThreatID(ctx context.Context, orgID int64, p db.UpsertBareEnrichedThreatParams) (int64, error) {
	return s.urls.UpsertBareThreat(ctx, orgID, p)
}

func (s *RepoStore) ApplyThreatEnrichment(ctx context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error {
	return s.enrich.ApplyThreatEnrichment(ctx, orgID, p)
}

func (s *RepoStore) GetPriorEnrichedThreat(ctx context.Context, orgID int64, domain string, excludeID int64) (db.EnrichedThreat, error) {
	return s.enrich.GetPriorEnrichedThreat(ctx, orgID, domain, excludeID)
}

func (s *RepoStore) ListEmailURLs(ctx context.Context, orgID, internalID int64, fetchedAt pgtype.Timestamptz) ([]db.ListEmailURLsRow, error) {
	return s.enrich.ListEmailURLs(ctx, orgID, internalID, fetchedAt)
}

func (s *RepoStore) RecordTIMatch(ctx context.Context, orgID int64, p db.InsertEmailURLTIMatchParams) error {
	return s.enrich.RecordTIMatch(ctx, orgID, p)
}

func (s *RepoStore) UpsertResult(ctx context.Context, orgID int64, p db.UpsertEnrichmentResultParams) (int64, error) {
	return s.enrich.UpsertResult(ctx, orgID, p)
}

func (s *RepoStore) EnqueueJob(ctx context.Context, orgID int64, p db.EnqueueEnrichmentJobParams) (int64, error) {
	return s.enrich.EnqueueJob(ctx, orgID, p)
}

func (s *RepoStore) CompleteJob(ctx context.Context, orgID, jobID int64) error {
	return s.enrich.CompleteJob(ctx, orgID, jobID)
}
