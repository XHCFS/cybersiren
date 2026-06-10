// Package store is SVC-05's database side: the per-attachment hash lookup, the
// VirusTotal enrichment_results cache (24h TTL), the attachment_library malware
// flag UPSERT, and the email_attachments.risk_score UPDATE — all through the
// generated sqlc layer (D8: sqlc-only, no hand-written SQL).
//
// Every method runs inside an org-scoped transaction via the shared repository
// helper (WithOrgTx sets app.current_org_id), so RLS (G10 / spec §16 D12) is the
// real tenant boundary; attachment_library itself is a platform-global table
// (no org_id) but the partner writes (enrichment_results, email_attachments) are
// org-forced, so the GUC must be bound regardless.
//
// The Store interface lets the processor be unit-tested with a fake (no
// Postgres). The production implementation is RepoStore.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/pgconv"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// providerVirusTotal is the enrichment_results.provider label SVC-05 caches VT
// file reports under (§15 gap #3: SVC-05 owns the "virustotal" provider key).
const providerVirusTotal = "virustotal"

// HashVerdict is the attachment_library row SVC-05 reads for a sha256.
type HashVerdict struct {
	// Found is false when the binary has never been observed (no library row).
	Found bool
	// ID is attachment_library.id — the email_attachments.attachment_id FK and
	// the VT cache entity_id. Zero when not found.
	ID          int64
	IsMalicious bool
	RiskScore   int
	ThreatTags  []string
}

// CachedVT is a still-fresh VirusTotal result read from enrichment_results.
type CachedVT struct {
	// Found is false on a cache miss (no row, expired, or soft-deleted).
	Found           bool
	MaliciousVotes  int
	SuspiciousVotes int
	HarmlessVotes   int
	Raw             []byte
}

// Store is the slice of DB operations SVC-05's processor needs. Every method is
// org-scoped (RLS) in the production implementation.
type Store interface {
	// GetHashVerdict resolves the attachment_library row for sha256. A miss
	// returns HashVerdict{Found:false}, nil — not an error.
	GetHashVerdict(ctx context.Context, orgID int64, sha256 string) (HashVerdict, error)

	// GetFreshVT reads a non-expired cached VirusTotal result for the library
	// entity. A miss returns CachedVT{Found:false}, nil.
	GetFreshVT(ctx context.Context, orgID, attachmentLibraryID int64) (CachedVT, error)

	// CacheVT UPSERTs a VirusTotal file report into enrichment_results with the
	// supplied TTL (24h). entity_type='attachment', entity_id=attachmentLibraryID.
	CacheVT(ctx context.Context, orgID, attachmentLibraryID int64, fetchedAt time.Time, in VTCacheInput, ttl time.Duration) error

	// FlagMalicious UPSERTs the malware verdict onto attachment_library
	// (is_malicious=true, GREATEST risk_score, union threat_tags). Idempotent.
	FlagMalicious(ctx context.Context, orgID int64, sha256 string, riskScore int, threatTags []string) error

	// UpdateEmailAttachmentScore writes the per-attachment risk_score (and an
	// optional analysis_metadata blob) back onto the email_attachments link.
	// Returns the affected row count so the caller can detect a missing link
	// (0 rows ⇒ SVC-02 has not yet persisted this attachment).
	UpdateEmailAttachmentScore(ctx context.Context, in EmailAttachmentScore) (int64, error)
}

// VTCacheInput carries the parsed VT votes + raw body for the cache UPSERT.
type VTCacheInput struct {
	MaliciousVotes  int
	SuspiciousVotes int
	HarmlessVotes   int
	Raw             []byte
}

// EmailAttachmentScore is the per-attachment write-back input.
type EmailAttachmentScore struct {
	OrgID        int64
	InternalID   int64 // email_attachments.email_id == emails.internal_id
	FetchedAt    time.Time
	AttachmentID int64
	RiskScore    int
	// AnalysisMetadata, when non-empty, replaces email_attachments.analysis_metadata;
	// nil leaves the column unchanged (COALESCE in the query).
	AnalysisMetadata []byte
}

// RepoStore is the production Store over a single pgx pool.
type RepoStore struct {
	pool *pgxpool.Pool
}

// NewRepoStore builds a RepoStore. Returns nil when pool is nil.
func NewRepoStore(pool *pgxpool.Pool) *RepoStore {
	if pool == nil {
		return nil
	}
	return &RepoStore{pool: pool}
}

var _ Store = (*RepoStore)(nil)

func (s *RepoStore) GetHashVerdict(ctx context.Context, orgID int64, sha256 string) (HashVerdict, error) {
	var out HashVerdict
	err := repository.WithOrgTx(ctx, s.pool, orgID, func(q *dbsqlc.Queries) error {
		row, qerr := q.GetAttachmentBySha256(ctx, sha256)
		if qerr != nil {
			if errors.Is(qerr, pgx.ErrNoRows) {
				return nil // miss ⇒ Found stays false
			}
			return fmt.Errorf("get attachment by sha256: %w", qerr)
		}
		out = HashVerdict{
			Found:       true,
			ID:          row.ID,
			IsMalicious: row.IsMalicious.Valid && row.IsMalicious.Bool,
			RiskScore:   int4ToInt(row.RiskScore),
			ThreatTags:  row.ThreatTags,
		}
		return nil
	})
	if err != nil {
		return HashVerdict{}, fmt.Errorf("get hash verdict: %w", err)
	}
	return out, nil
}

func (s *RepoStore) GetFreshVT(ctx context.Context, orgID, attachmentLibraryID int64) (CachedVT, error) {
	var out CachedVT
	err := repository.WithOrgTx(ctx, s.pool, orgID, func(q *dbsqlc.Queries) error {
		row, qerr := q.GetFreshEnrichmentResult(ctx, dbsqlc.GetFreshEnrichmentResultParams{
			EntityType: dbsqlc.EntityTypeEnumAttachment,
			EntityID:   attachmentLibraryID,
			Provider:   providerVirusTotal,
		})
		if qerr != nil {
			if errors.Is(qerr, pgx.ErrNoRows) {
				return nil // cache miss / expired
			}
			return fmt.Errorf("get fresh enrichment result: %w", qerr)
		}
		out = CachedVT{
			Found:           true,
			MaliciousVotes:  int4ToInt(row.MaliciousVotes),
			SuspiciousVotes: int4ToInt(row.SuspiciousVotes),
			HarmlessVotes:   int4ToInt(row.HarmlessVotes),
			Raw:             row.RawResponse,
		}
		return nil
	})
	if err != nil {
		return CachedVT{}, fmt.Errorf("get fresh vt cache: %w", err)
	}
	return out, nil
}

func (s *RepoStore) CacheVT(
	ctx context.Context,
	orgID, attachmentLibraryID int64,
	fetchedAt time.Time,
	in VTCacheInput,
	ttl time.Duration,
) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	ttlSeconds := int32(ttl.Seconds())
	err := repository.WithOrgTx(ctx, s.pool, orgID, func(q *dbsqlc.Queries) error {
		_, qerr := q.UpsertEnrichmentResult(ctx, dbsqlc.UpsertEnrichmentResultParams{
			EntityType:      dbsqlc.EntityTypeEnumAttachment,
			EntityID:        attachmentLibraryID,
			EmailFetchedAt:  pgconv.TimestamptzOrNull(fetchedAt),
			Provider:        providerVirusTotal,
			RawResponse:     in.Raw,
			MaliciousVotes:  pgconv.Int4OrNull(int32(in.MaliciousVotes)),
			HarmlessVotes:   pgconv.Int4OrNull(int32(in.HarmlessVotes)),
			SuspiciousVotes: pgconv.Int4OrNull(int32(in.SuspiciousVotes)),
			ReputationScore: pgtype.Float8{},
			TtlSeconds:      pgconv.Int4OrNull(ttlSeconds),
			ExpiresAt:       pgconv.TimestamptzOrNull(time.Now().Add(ttl)),
			OrgID:           pgconv.Int8(orgID),
		})
		if qerr != nil {
			return fmt.Errorf("upsert enrichment result: %w", qerr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cache vt result: %w", err)
	}
	return nil
}

func (s *RepoStore) FlagMalicious(ctx context.Context, orgID int64, sha256 string, riskScore int, threatTags []string) error {
	if threatTags == nil {
		threatTags = []string{}
	}
	err := repository.WithOrgTx(ctx, s.pool, orgID, func(q *dbsqlc.Queries) error {
		return q.UpsertMalwareHash(ctx, dbsqlc.UpsertMalwareHashParams{
			Sha256:     sha256,
			RiskScore:  pgconv.Int4OrNull(int32(riskScore)),
			ThreatTags: threatTags,
		})
	})
	if err != nil {
		return fmt.Errorf("flag malicious hash: %w", err)
	}
	return nil
}

func (s *RepoStore) UpdateEmailAttachmentScore(ctx context.Context, in EmailAttachmentScore) (int64, error) {
	var affected int64
	err := repository.WithOrgTx(ctx, s.pool, in.OrgID, func(q *dbsqlc.Queries) error {
		n, qerr := q.UpdateEmailAttachmentRiskScore(ctx, dbsqlc.UpdateEmailAttachmentRiskScoreParams{
			EmailID:          in.InternalID,
			EmailFetchedAt:   pgconv.TimestamptzOrNull(in.FetchedAt),
			AttachmentID:     in.AttachmentID,
			RiskScore:        pgconv.Int4OrNull(int32(in.RiskScore)),
			AnalysisMetadata: nilIfEmpty(in.AnalysisMetadata),
		})
		if qerr != nil {
			return fmt.Errorf("update email attachment risk score: %w", qerr)
		}
		affected = n
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("update email_attachments risk_score: %w", err)
	}
	return affected, nil
}

func int4ToInt(v pgtype.Int4) int {
	if !v.Valid {
		return 0
	}
	return int(v.Int32)
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
