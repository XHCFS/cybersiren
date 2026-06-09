// Package persist owns the single-transaction database write performed by
// SVC-08 Decision Engine for every emails.scored message.
//
// All primary writes happen inside one pgx transaction, scoped to the email's
// org via the app.current_org_id RLS GUC (spec §16 D12):
//  1. UPSERT campaigns (returns campaign_id, is_new, email_count_after).
//  2. UPDATE emails (sets risk scores, campaign_id, analysis_metadata).
//  3. INSERT verdicts (append-only).
//  4. INSERT rule_hits (one per fired rule, append-only).
//  5. UPDATE verdicts.kafka_verdict_wire (immutable emails.verdict JSON for idempotent republish).
//
// Failure of any step rolls back the transaction; the Kafka offset is not
// committed and the message is redelivered after restart/rebalance.
//
// Every statement is a sqlc-generated method (db.New(tx)); the canonical SQL
// lives in db/queries/{campaigns,verdicts,emails_scores,email_campaign_snapshot}.sql.
package persist

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	rulespkg "github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// Input bundles every value the single-transaction write needs. The
// engine builds it from the inbound emails.scored message + blender
// output + rule evaluation result + campaign-history lookup.
type Input struct {
	OrgID      int64
	InternalID int64
	FetchedAt  time.Time

	RiskScore           int
	HeaderRiskScore     *int
	ContentRiskScore    *int
	URLRiskScore        *int
	AttachmentRiskScore *int

	Fingerprint  string
	CampaignName string // optional human-readable; "" → DB falls back to ''
	ThreatType   string // optional
	TargetBrand  string // optional

	Label         string
	Confidence    float64
	VerdictSource string
	ModelVersion  string

	Fired []rulespkg.FiredRule

	AnalysisMetadata []byte // JSONB blob; pass nil to leave the column NULL

	// VerdictWireBuilder, if non-nil, runs inside the same transaction after
	// INSERT verdict + rule_hits; the returned JSON is stored as
	// verdicts.kafka_verdict_wire for byte-accurate Kafka republish on replay.
	VerdictWireBuilder func(VerdictWireContext) ([]byte, error)
}

// VerdictWireContext is passed to Input.VerdictWireBuilder.
type VerdictWireContext struct {
	VerdictID  int64
	CampaignID int64
	IsNew      bool
	EmailCount int
}

// Output is what the engine needs from the writer to publish the
// emails.verdict message.
type Output struct {
	CampaignID int64
	IsNew      bool
	EmailCount int
	VerdictID  int64
	// DedupeSkip is true when a verdict row already existed for this email
	// partition (Kafka redelivery or unique-race retry).
	DedupeSkip bool
	// KafkaVerdictWire is the DB-stored emails.verdict JSON when present
	// (preferred over recomputation for republish).
	KafkaVerdictWire []byte
}

// Writer runs the single-tx database write. Retries with backoff on
// transient errors; never retries when the context is cancelled.
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

// Write executes the full transaction with retry-with-backoff. Returns
// the campaign linkage info needed to build emails.verdict.
func (w *Writer) Write(ctx context.Context, in Input) (Output, error) {
	if w == nil || w.pool == nil {
		return Output{}, errors.New("decision writer: not initialised")
	}

	attempts := w.maxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Output{}, err
		}
		out, err := w.runOnce(ctx, in)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Output{}, err
		}
		backoff := backoffDuration(attempt)
		w.log.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", attempts).
			Dur("backoff", backoff).
			Int64("email_internal_id", in.InternalID).
			Msg("decision tx failed; retrying")

		select {
		case <-ctx.Done():
			return Output{}, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return Output{}, fmt.Errorf("decision tx exhausted retries: %w", lastErr)
}

func (in Input) validate() error {
	if in.OrgID <= 0 {
		return fmt.Errorf("decision input: org_id must be > 0")
	}
	if in.InternalID <= 0 {
		return fmt.Errorf("decision input: internal_id must be > 0")
	}
	if in.FetchedAt.IsZero() {
		return fmt.Errorf("decision input: fetched_at required")
	}
	if in.Fingerprint == "" {
		return fmt.Errorf("decision input: fingerprint required")
	}
	return nil
}

func (w *Writer) runOnce(ctx context.Context, in Input) (Output, error) {
	if err := in.validate(); err != nil {
		return Output{}, err
	}

	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Output{}, fmt.Errorf("begin decision tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// G10/D12 RLS: bind the tenant boundary for this transaction. Every table
	// this writer touches (emails, verdicts, campaigns, rule_hits) is
	// FORCE ROW LEVEL SECURITY; without the GUC the tenant_isolation policy
	// denies all rows once the app connects as a non-bypass role.
	if err := repository.SetOrgGUC(ctx, tx, in.OrgID); err != nil {
		return Output{}, fmt.Errorf("set org guc: %w", err)
	}

	q := dbsqlc.New(tx)

	existingRow, err := q.FindExistingVerdictForEmail(ctx, dbsqlc.FindExistingVerdictForEmailParams{
		Column1:  dbsqlc.EntityTypeEnumEmail,
		EntityID: in.InternalID,
		Column3:  fetchedAtParam(in.FetchedAt),
	})
	existingVerdict := existingRow.ID
	storedWire := kafkaWireBytes(existingRow.KafkaWire)
	if err == nil {
		// LEFT JOIN: campaign_id may be NULL when the campaign was
		// soft-deleted between the original commit and this replay, or
		// on legacy rows that never linked one. The stored
		// kafka_verdict_wire is what republish actually needs; live
		// campaign linkage is best-effort here.
		snap, scanErr := q.GetEmailCampaignSnapshot(ctx, dbsqlc.GetEmailCampaignSnapshotParams{
			InternalID: in.InternalID,
			Column2:    fetchedAtParam(in.FetchedAt),
		})
		campID := snap.CampaignID
		emailCount := emailCountToInt32(snap.EmailCount)
		switch {
		case scanErr == nil:
			// fall through
		case errors.Is(scanErr, pgx.ErrNoRows):
			// emails row itself missing — log and proceed; the stored
			// wire is the source of truth for republish.
			w.log.Warn().
				Int64("email_internal_id", in.InternalID).
				Msg("dedupe replay: emails row missing; republishing from stored wire")
		default:
			return Output{}, fmt.Errorf("idempotent replay: load email campaign row: %w", scanErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return Output{}, fmt.Errorf("commit idempotent decision tx: %w", err)
		}
		var campOut int64
		if campID.Valid {
			campOut = campID.Int64
		}
		return Output{
			CampaignID:       campOut,
			IsNew:            false,
			EmailCount:       int(emailCount),
			VerdictID:        existingVerdict,
			DedupeSkip:       true,
			KafkaVerdictWire: storedWire,
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Output{}, fmt.Errorf("probe existing verdict: %w", err)
	}

	// 1. UPSERT campaign — needed first so we have the campaign_id to
	// record on the emails row.
	campRow, err := q.UpsertCampaign(ctx, dbsqlc.UpsertCampaignParams{
		OrgID:       requiredOrgID(in.OrgID),
		Fingerprint: in.Fingerprint,
		Name:        in.CampaignName,
		ThreatType:  nullableString(in.ThreatType),
		TargetBrand: nullableString(in.TargetBrand),
		RiskScore:   pgtype.Int4{Int32: clampInt32(in.RiskScore, 0, 100), Valid: true},
		Tags:        []string{}, // empty array; future enrichment can populate
	})
	if err != nil {
		return Output{}, fmt.Errorf("upsert campaign: %w", err)
	}
	campID := campRow.ID
	isNew := campRow.IsNew
	emailCount := emailCountToInt32(campRow.EmailCount)

	// 2. UPDATE emails row with final scores + campaign linkage.
	rowsAffected, err := q.UpdateEmailScores(ctx, dbsqlc.UpdateEmailScoresParams{
		InternalID:          in.InternalID,
		FetchedAt:           fetchedAtParam(in.FetchedAt),
		RiskScore:           pgtype.Int4{Int32: clampInt32(in.RiskScore, 0, 100), Valid: true},
		HeaderRiskScore:     nullableInt32Ptr(in.HeaderRiskScore),
		ContentRiskScore:    nullableInt32Ptr(in.ContentRiskScore),
		UrlRiskScore:        nullableInt32Ptr(in.URLRiskScore),
		AttachmentRiskScore: nullableInt32Ptr(in.AttachmentRiskScore),
		CampaignID:          pgtype.Int8{Int64: campID, Valid: true},
		Column9:             nullableJSONBBytes(in.AnalysisMetadata),
	})
	if err != nil {
		return Output{}, fmt.Errorf("update emails: %w", err)
	}
	if rowsAffected != 1 {
		return Output{}, fmt.Errorf(
			"update emails: expected exactly 1 row updated for (internal_id,fetched_at)=(%d,%v), got %d",
			in.InternalID, in.FetchedAt.UTC(), rowsAffected,
		)
	}

	// 3. INSERT verdict (append-only).
	verdictID, err := q.InsertVerdict(ctx, dbsqlc.InsertVerdictParams{
		EntityType:     dbsqlc.EntityTypeEnumEmail,
		EntityID:       in.InternalID,
		EmailFetchedAt: fetchedAtParam(in.FetchedAt),
		Label:          dbsqlc.VerdictLabel(in.Label),
		Confidence:     pgtype.Float8{Float64: in.Confidence, Valid: true},
		Source:         dbsqlc.VerdictSource(in.VerdictSource),
		ModelVersion:   nullableString(in.ModelVersion),
		OrgID:          requiredOrgID(in.OrgID),
	})
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return Output{}, fmt.Errorf("insert verdict: pipeline unique conflict (retry should dedupe): %w", err)
		}
		return Output{}, fmt.Errorf("insert verdict: %w", err)
	}

	// 4. INSERT rule_hits (one per fired rule).
	for _, fr := range in.Fired {
		if _, err := q.InsertRuleHit(ctx, dbsqlc.InsertRuleHitParams{
			RuleID:         pgtype.Int8{Int64: fr.Rule.ID, Valid: true},
			RuleVersion:    fr.Rule.Version,
			EntityType:     dbsqlc.EntityTypeEnumEmail,
			EntityID:       in.InternalID,
			EmailFetchedAt: fetchedAtParam(in.FetchedAt),
			ScoreImpact:    int32(fr.Rule.ScoreImpact),
			MatchDetail:    fr.MatchDetail,
		}); err != nil {
			return Output{}, fmt.Errorf("insert rule_hit (rule_id=%d): %w", fr.Rule.ID, err)
		}
	}

	if in.VerdictWireBuilder != nil {
		wire, werr := in.VerdictWireBuilder(VerdictWireContext{
			VerdictID:  verdictID,
			CampaignID: campID,
			IsNew:      isNew,
			EmailCount: int(emailCount),
		})
		if werr != nil {
			return Output{}, fmt.Errorf("verdict wire builder: %w", werr)
		}
		if len(wire) > 0 {
			if err := q.UpdateVerdictKafkaWire(ctx, dbsqlc.UpdateVerdictKafkaWireParams{
				Column1: wire,
				ID:      verdictID,
			}); err != nil {
				return Output{}, fmt.Errorf("persist kafka_verdict_wire: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Output{}, fmt.Errorf("commit decision tx: %w", err)
	}
	return Output{
		CampaignID: campID,
		IsNew:      isNew,
		EmailCount: int(emailCount),
		VerdictID:  verdictID,
	}, nil
}

// GetCampaignHistory reads existing campaign state for the empirical-Bayes
// nudge. Returns (nil, nil) when no campaign row exists for the (org_id,
// fingerprint) pair.
func (w *Writer) GetCampaignHistory(ctx context.Context, orgID int64, fingerprint string) (*CampaignHistory, error) {
	if w == nil || w.pool == nil {
		return nil, errors.New("decision writer: not initialised")
	}

	// campaigns is RLS-forced, so the read must run inside an org-scoped tx
	// (G10/D12); a bare pool read would return zero rows once the app connects
	// as a non-bypass role.
	var (
		out   *CampaignHistory
		found bool
	)
	err := repository.WithOrgTx(ctx, w.pool, orgID, func(q *dbsqlc.Queries) error {
		row, qerr := q.GetCampaignByFingerprint(ctx, dbsqlc.GetCampaignByFingerprintParams{
			OrgID:       nullableInt8(orgID),
			Fingerprint: fingerprint,
		})
		if qerr != nil {
			if errors.Is(qerr, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("get campaign by fingerprint: %w", qerr)
		}
		rs := 0
		if row.RiskScore.Valid {
			rs = int(row.RiskScore.Int32)
		}
		out = &CampaignHistory{
			CampaignID: row.ID,
			RiskScore:  rs,
			EmailCount: int(emailCountToInt32(row.EmailCount)),
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get campaign history: %w", err)
	}
	if !found {
		return nil, nil
	}
	return out, nil
}

// CampaignHistory mirrors campaign.History; declared here so the persist
// package's public API does not pull in the campaign package.
type CampaignHistory struct {
	CampaignID int64
	RiskScore  int
	EmailCount int
}

func backoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > 5*time.Second {
			d = 5 * time.Second
			break
		}
	}
	return d
}

// ----------------------------------------------------------------------
// pgtype helpers
// ----------------------------------------------------------------------

func nullableString(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func nullableInt8(v int64) pgtype.Int8 {
	return pgtype.Int8{Int64: v, Valid: v != 0}
}

func requiredOrgID(v int64) pgtype.Int8 {
	return pgtype.Int8{Int64: v, Valid: true}
}

func fetchedAtParam(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func nullableInt32Ptr(v *int) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: clampInt32(*v, 0, 100), Valid: true}
}

// nullableJSONBBytes returns nil for an empty blob so sqlc's []byte parameter
// is encoded as SQL NULL (leaving analysis_metadata unchanged via COALESCE),
// or the blob itself otherwise.
func nullableJSONBBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// kafkaWireBytes normalises the kafka_wire column, which sqlc types as
// interface{} because COALESCE(kafka_verdict_wire::text, ”) defeats type
// inference. pgx decodes the TEXT result as a Go string; an empty string means
// "no stored wire" (the COALESCE default), matching the original NULL handling.
func kafkaWireBytes(v any) []byte {
	if s, ok := v.(string); ok && s != "" {
		return []byte(s)
	}
	return nil
}

// emailCountToInt32 normalises the email_count column, which sqlc types as
// interface{} because it is a COALESCE expression. pgx decodes the underlying
// INT as int32/int64 depending on the path; handle both plus a nil (no row).
func emailCountToInt32(v any) int32 {
	switch n := v.(type) {
	case int32:
		return n
	case int64:
		return int32(n)
	case int:
		return int32(n)
	default:
		return 0
	}
}

func clampInt32(v, lo, hi int) int32 {
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return int32(v)
}
