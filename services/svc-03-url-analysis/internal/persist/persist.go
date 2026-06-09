// Package persist owns SVC-03's enrichment persistence — the DB side of
// ARCH-SPEC §14 step 3a. After the Kafka handler has scored every URL in an
// email (Guard → L1 → TI → L2), it hands the per-URL scan results here to be
// written through the generated sqlc layer:
//
//   - enriched_threats UPDATE — the ~28-col COALESCE UPDATE applying SVC-03's
//     risk_score / threat_type / analysis_metadata onto the bare row SVC-02
//     inserted (resolved by URL via the idempotent bare upsert).
//   - email_url_ti_matches INSERT — the TI-feed-match audit trail, one row per
//     matched (email_url, ti_indicator).
//   - enrichment_results UPSERT — the per-provider enrichment cache (TTL-bound).
//   - enrichment_jobs WRITE — the job-lifecycle row tracking the enrichment run.
//   - enriched_threats READ — the prior-email lookup that lets SVC-03 reuse a
//     host's earlier enrichment instead of re-running it.
//
// This package does NO scoring: every value written is one the handler already
// computed (P1.2 is persistence-only). All writes flow through org-scoped
// transactions so RLS (G10, app.current_org_id) is the real tenant boundary;
// the store interface is satisfied by the shared repository layer, which sets
// the GUC on every tx via WithOrgTx.
package persist

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// enrichmentJobType is the enrichment_jobs.job_type SVC-03's URL enrichment
// runs under. url_scan is the closest enum member (migration 026 job_type) to
// "fused URL enrichment"; whois/ssl_cert/ip_geo are component-level types the
// async workers use. SVC-03 records the run as a single url_scan job.
const enrichmentJobType = db.JobTypeUrlScan

// enrichmentProvider labels the enrichment_results cache row SVC-03 writes. The
// fused L2 verdict is SVC-03's own enrichment output (not a third-party feed),
// so it is cached under the service's own provider key rather than e.g.
// "virustotal" (which SVC-05 owns).
const enrichmentProvider = "url_fusion"

// Default enrichment_jobs knobs. SVC-03 enriches synchronously inside the
// handler, so the job row is a completed audit record rather than a queue entry;
// these mirror the table defaults (migration 026) for a normal-priority run.
const (
	defaultMaxAttempts    = 3
	defaultTimeoutSeconds = 600
	defaultPriority       = 5
)

// EnrichmentStore is the slice of the shared repository layer SVC-03 persistence
// needs. It is an interface so the orchestration is unit-testable with a fake
// (no Postgres); the production implementation is the shared
// repository.EnrichmentRepository + repository.URLRepository, both of which set
// app.current_org_id on every transaction (G10).
type EnrichmentStore interface {
	// ResolveThreatID idempotently upserts the bare enriched_threats row for a
	// URL and returns its id (the email_urls.threat_id FK). SVC-02 already
	// inserted this row; the upsert is idempotent (ON CONFLICT refreshes
	// last_seen), so calling it again is the canonical way to resolve the
	// threat id by URL without a positional join against analysis.urls.
	ResolveThreatID(ctx context.Context, orgID int64, p db.UpsertBareEnrichedThreatParams) (int64, error)
	// ApplyThreatEnrichment runs the enriched_threats UPDATE on threat row p.ID.
	ApplyThreatEnrichment(ctx context.Context, orgID int64, p db.UpdateEnrichedThreatEnrichmentParams) error
	// GetPriorEnrichedThreat reads this org's most-recently-enriched row for a
	// domain (excluding excludeID). Returns repository.ErrNoPriorEnrichment on a
	// miss.
	GetPriorEnrichedThreat(ctx context.Context, orgID int64, domain string, excludeID int64) (db.EnrichedThreat, error)
	// ListEmailURLs returns the email_urls SVC-02 persisted for an email so each
	// scored URL can be mapped to its email_url id (for the TI-match audit).
	ListEmailURLs(ctx context.Context, orgID, internalID int64, fetchedAt pgtype.Timestamptz) ([]db.ListEmailURLsRow, error)
	// RecordTIMatch appends one email_url_ti_matches audit row.
	RecordTIMatch(ctx context.Context, orgID int64, p db.InsertEmailURLTIMatchParams) error
	// UpsertResult caches a provider's enrichment in enrichment_results.
	UpsertResult(ctx context.Context, orgID int64, p db.UpsertEnrichmentResultParams) (int64, error)
	// EnqueueJob writes an enrichment_jobs row and returns its id.
	EnqueueJob(ctx context.Context, orgID int64, p db.EnqueueEnrichmentJobParams) (int64, error)
	// CompleteJob marks an enrichment_jobs row completed.
	CompleteJob(ctx context.Context, orgID, jobID int64) error
}

// URLResult is the persistence-facing projection of one scored URL. The handler
// fills it from its in-memory scan; persist computes nothing from it beyond
// shaping the DB rows. RawURL is the as-extracted URL (matches what SVC-02 keyed
// the bare enriched_threats row on); Domain/TLD/Apex are the host parts the
// handler already derived. PriorEnrichment, when true, is recorded in the
// analysis_metadata blob.
type URLResult struct {
	RawURL     string
	Normalized string
	Domain     string // hostname (enriched_threats.domain)
	TLD        string
	Apex       string

	Score    int    // URL risk score [0,100] the handler computed
	Label    string // "legitimate" | "suspicious" | "phishing"
	GuardHit string

	TIMatch       bool
	TIThreatType  string
	TIRiskScore   int
	TIIndicatorID int64 // ti_indicators.id when known (0 ⇒ no audit row)

	MLDeployP  float64
	MLVerdict  string
	MLCacheHit bool

	// PriorEnrichmentReused is set by Persist when GetPriorEnrichedThreat hit.
	PriorEnrichmentReused bool
}

// Email is the per-email persistence input the handler hands to Persist.
type Email struct {
	OrgID      int64
	InternalID int64 // emails.internal_id (carried by SVC-02; interim == email_id)
	FetchedAt  time.Time
	URLs       []URLResult
}

// Persister orchestrates the five enrichment writes for one email through the
// org-scoped repository layer. It is safe to share across handler goroutines:
// it holds only the store, metrics, and logger.
type Persister struct {
	store   EnrichmentStore
	metrics *Metrics
	log     zerolog.Logger
}

// New constructs a Persister over store. metrics may be nil (no-op).
func New(store EnrichmentStore, metrics *Metrics, log zerolog.Logger) *Persister {
	return &Persister{store: store, metrics: metrics, log: log}
}

// Persist writes the enrichment of one email. It is best-effort per URL: a write
// failure for one URL is logged and counted but does not abort the others, so a
// transient DB error never strands the rest of the email. It returns the first
// error encountered (so the caller can decide whether to NACK the Kafka
// message), after attempting every URL.
func (p *Persister) Persist(ctx context.Context, e Email) error {
	if p == nil || p.store == nil {
		return errors.New("persist: nil persister")
	}
	if e.OrgID <= 0 {
		// Without an org id every RLS-scoped write would be rejected by
		// WithOrgTx; surface it rather than emit N failing transactions.
		return repository.ErrNoOrgContext
	}
	if len(e.URLs) == 0 {
		return nil
	}

	fetchedAt := pgTimestamptz(e.FetchedAt)

	// Resolve the email_urls SVC-02 persisted so TI matches can be audited
	// against the correct email_url id. A miss (SVC-02 P1.1 not yet wired, or an
	// id mismatch) is not fatal — the threat-level writes still run; only the
	// per-email_url audit row is skipped.
	threatToEmailURL := p.emailURLIndex(ctx, e)

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	for i := range e.URLs {
		u := &e.URLs[i]
		if err := p.persistURL(ctx, e, fetchedAt, u, threatToEmailURL); err != nil {
			p.metrics.IncWrite("url", "error")
			p.log.Warn().Err(err).
				Int64("internal_id", e.InternalID).
				Str("url", u.RawURL).
				Msg("persist enrichment for URL failed")
			note(err)
			continue
		}
		p.metrics.IncWrite("url", "ok")
	}
	return firstErr
}

// emailURLIndex builds a threat_id → email_url_id map from the email_urls
// SVC-02 persisted, so a TI match can be attributed to the right email_url row.
// Returns an empty (non-nil) map when SVC-02 has not yet persisted the URLs.
func (p *Persister) emailURLIndex(ctx context.Context, e Email) map[int64]int64 {
	idx := make(map[int64]int64)
	rows, err := p.store.ListEmailURLs(ctx, e.OrgID, e.InternalID, pgTimestamptz(e.FetchedAt))
	if err != nil {
		p.log.Warn().Err(err).
			Int64("internal_id", e.InternalID).
			Msg("list email_urls failed; TI-match audit rows will be skipped")
		return idx
	}
	for _, r := range rows {
		if r.ThreatID.Valid {
			idx[r.ThreatID.Int64] = r.ID
		}
	}
	return idx
}

// persistURL runs the five-part write for a single URL.
func (p *Persister) persistURL(
	ctx context.Context,
	e Email,
	fetchedAt pgtype.Timestamptz,
	u *URLResult,
	threatToEmailURL map[int64]int64,
) error {
	// (1) Resolve the enriched_threats row id by URL (idempotent bare upsert).
	threatID, err := p.store.ResolveThreatID(ctx, e.OrgID, db.UpsertBareEnrichedThreatParams{
		Url:    u.RawURL,
		Domain: pgText(u.Domain),
		Tld:    pgText(u.TLD),
		OrgID:  pgInt8(e.OrgID),
	})
	if err != nil {
		return err
	}

	// (2) Prior-email enrichment READ — reuse a host's earlier enrichment.
	prior, priorErr := p.store.GetPriorEnrichedThreat(ctx, e.OrgID, u.Domain, threatID)
	switch {
	case priorErr == nil:
		u.PriorEnrichmentReused = true
		p.metrics.IncPrior("hit")
		p.log.Debug().
			Int64("prior_threat_id", prior.ID).
			Str("domain", u.Domain).
			Msg("reusing prior-email enrichment")
	case errors.Is(priorErr, repository.ErrNoPriorEnrichment):
		p.metrics.IncPrior("miss")
	default:
		// A read error is non-fatal — fall through to writing fresh enrichment.
		p.metrics.IncPrior("error")
		p.log.Warn().Err(priorErr).Str("domain", u.Domain).Msg("prior-enrichment read failed")
	}

	// (3) enriched_threats UPDATE — persist this URL's computed enrichment.
	if err := p.store.ApplyThreatEnrichment(ctx, e.OrgID, p.buildEnrichmentUpdate(threatID, u)); err != nil {
		return err
	}

	// (4) enrichment_results UPSERT — cache the fused verdict for this entity.
	if _, err := p.store.UpsertResult(ctx, e.OrgID, p.buildEnrichmentResult(threatID, fetchedAt, e.OrgID, u)); err != nil {
		return err
	}

	// (5) email_url_ti_matches INSERT — audit the TI feed match (when one fired
	// and we resolved the owning email_url row).
	if u.TIMatch && u.TIIndicatorID > 0 {
		if emailURLID, ok := threatToEmailURL[threatID]; ok {
			if err := p.store.RecordTIMatch(ctx, e.OrgID, db.InsertEmailURLTIMatchParams{
				EmailUrlID:    emailURLID,
				TiIndicatorID: u.TIIndicatorID,
				MatchType:     tiMatchType(u),
			}); err != nil {
				return err
			}
			p.metrics.IncWrite("ti_match", "ok")
		} else {
			p.metrics.IncWrite("ti_match", "skipped")
		}
	}

	// (6) enrichment_jobs WRITE — record the lifecycle row for this run. SVC-03
	// enriches inline, so the job is enqueued and immediately completed: it is an
	// audit/lineage record, not a queue entry a worker will later claim.
	jobID, err := p.store.EnqueueJob(ctx, e.OrgID, db.EnqueueEnrichmentJobParams{
		JobType:        enrichmentJobType,
		EntityType:     db.EntityTypeEnumThreat,
		EntityID:       threatID,
		EmailFetchedAt: fetchedAt,
		MaxAttempts:    defaultMaxAttempts,
		TimeoutSeconds: defaultTimeoutSeconds,
		Priority:       defaultPriority,
		OrgID:          pgInt8(e.OrgID),
	})
	if err != nil {
		return err
	}
	if err := p.store.CompleteJob(ctx, e.OrgID, jobID); err != nil {
		return err
	}
	p.metrics.IncWrite("job", "ok")

	return nil
}

// buildEnrichmentUpdate shapes the enriched_threats UPDATE params from the
// already-computed scan. Only the columns SVC-03 actually derives are set; the
// rest stay NULL and the COALESCE query leaves them untouched (so a later WHOIS/
// geo enrichment pass — or SVC-04 — does not get clobbered). risk_score and
// threat_type are the URL verdict; analysis_metadata captures the signal trail.
func (p *Persister) buildEnrichmentUpdate(threatID int64, u *URLResult) db.UpdateEnrichedThreatEnrichmentParams {
	params := db.UpdateEnrichedThreatEnrichmentParams{
		ID:        threatID,
		RiskScore: pgInt4(int32(u.Score)),
	}
	if tt := threatTypeForLabel(u.Label); tt != "" {
		params.ThreatType = pgText(tt)
	}
	if blob := u.analysisMetadata(); len(blob) > 0 {
		params.Column30 = blob // analysis_metadata jsonb
	}
	return params
}

// buildEnrichmentResult shapes the enrichment_results UPSERT params. The fused
// L2 verdict is cached as the provider response so a re-observation of the same
// entity within the TTL can reuse it. entity_type = 'threat' + entity_id =
// enriched_threats.id is the URL-entity mapping the schema uses (the enum has no
// 'url' member; enrichment_results.entity_id for URL entities is the shared
// enriched_threats.id).
func (p *Persister) buildEnrichmentResult(
	threatID int64,
	fetchedAt pgtype.Timestamptz,
	orgID int64,
	u *URLResult,
) db.UpsertEnrichmentResultParams {
	const ttlSeconds = 24 * 60 * 60 // 24h, mirrors the URL-enrichment cache TTL
	return db.UpsertEnrichmentResultParams{
		EntityType:      db.EntityTypeEnumThreat,
		EntityID:        threatID,
		EmailFetchedAt:  fetchedAt,
		Provider:        enrichmentProvider,
		RawResponse:     u.analysisMetadata(),
		ReputationScore: pgFloat8(float64(u.Score)),
		TtlSeconds:      pgInt4(ttlSeconds),
		ExpiresAt:       pgTimestamptz(time.Now().Add(ttlSeconds * time.Second)),
		OrgID:           pgInt8(orgID),
	}
}

// analysisMetadata serialises the URL's signal trail into the analysis_metadata
// jsonb blob. Returns nil on a marshal error so the COALESCE UPDATE leaves the
// column unchanged rather than writing malformed JSON.
func (u *URLResult) analysisMetadata() []byte {
	meta := map[string]any{
		"source":                  "svc-03-url-analysis",
		"label":                   u.Label,
		"score":                   u.Score,
		"ti_match":                u.TIMatch,
		"prior_enrichment_reused": u.PriorEnrichmentReused,
	}
	if u.Normalized != "" {
		meta["normalized_url"] = u.Normalized
	}
	if u.GuardHit != "" {
		meta["guard_hit"] = u.GuardHit
	}
	if u.TIThreatType != "" {
		meta["ti_threat_type"] = u.TIThreatType
	}
	if u.TIMatch {
		meta["ti_risk_score"] = u.TIRiskScore
	}
	if u.MLVerdict != "" {
		meta["ml_verdict"] = u.MLVerdict
		meta["ml_deploy_p"] = u.MLDeployP
		meta["ml_cache_hit"] = u.MLCacheHit
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	return b
}

// threatTypeForLabel maps SVC-03's URL label to the enriched_threats.threat_type
// vocabulary. "legitimate" maps to empty so a benign re-observation does not
// overwrite a prior malicious classification (COALESCE leaves it unchanged).
func threatTypeForLabel(label string) string {
	switch label {
	case "phishing":
		return "phishing"
	case "suspicious":
		return "suspicious"
	default:
		return ""
	}
}

// tiMatchType maps a URL scan to the email_url_ti_matches.match_type CHECK
// vocabulary ('exact','domain','ip','cidr','hash'). SVC-03's TI feed match is a
// domain/apex blocklist hit, so 'domain' is the accurate default; an exact-URL
// indicator is reported as 'exact'.
func tiMatchType(u *URLResult) string {
	if u.TIThreatType == "url" {
		return "exact"
	}
	return "domain"
}
