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

	var existingVerdict int64
	var wireText pgtype.Text
	err = tx.QueryRow(ctx, queryFindExistingVerdict,
		string(dbsqlc.EntityTypeEnumEmail),
		in.InternalID,
		fetchedAtParam(in.FetchedAt),
	).Scan(&existingVerdict, &wireText)
	var storedWire []byte
	if wireText.Valid && wireText.String != "" {
		storedWire = []byte(wireText.String)
	}
	if err == nil {
		var campID int64
		var emailCount int32
		if err := tx.QueryRow(ctx, queryEmailCampaignSnapshot,
			in.InternalID,
			fetchedAtParam(in.FetchedAt),
		).Scan(&campID, &emailCount); err != nil {
			return Output{}, fmt.Errorf("idempotent replay: load email campaign row: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return Output{}, fmt.Errorf("commit idempotent decision tx: %w", err)
		}
		return Output{
			CampaignID:       campID,
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
	var (
		campID     int64
		isNew      bool
		emailCount int32
	)
	err = tx.QueryRow(ctx, queryUpsertCampaign,
		requiredOrgID(in.OrgID),
		in.Fingerprint,
		nullableString(in.CampaignName),
		nullableString(in.ThreatType),
		nullableString(in.TargetBrand),
		clampInt32(in.RiskScore, 0, 100),
		[]string{}, // tags — empty array; future enrichment can populate
	).Scan(&campID, &isNew, &emailCount)
	if err != nil {
		return Output{}, fmt.Errorf("upsert campaign: %w", err)
	}

	// 2. UPDATE emails row with final scores + campaign linkage.
	tag, err := tx.Exec(ctx, queryUpdateEmailScores,
		in.InternalID,
		fetchedAtParam(in.FetchedAt),
		clampInt32(in.RiskScore, 0, 100),
		nullableInt32Ptr(in.HeaderRiskScore),
		nullableInt32Ptr(in.ContentRiskScore),
		nullableInt32Ptr(in.URLRiskScore),
		nullableInt32Ptr(in.AttachmentRiskScore),
		pgtype.Int8{Int64: campID, Valid: true},
		nullableJSONB(in.AnalysisMetadata),
	)
	if err != nil {
		return Output{}, fmt.Errorf("update emails: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Output{}, fmt.Errorf(
			"update emails: expected exactly 1 row updated for (internal_id,fetched_at)=(%d,%v), got %d",
			in.InternalID, in.FetchedAt.UTC(), tag.RowsAffected(),
		)
	}

	// 3. INSERT verdict (append-only).
	var verdictID int64
	if err := tx.QueryRow(ctx, queryInsertVerdict,
		string(dbsqlc.EntityTypeEnumEmail),
		in.InternalID,
		fetchedAtParam(in.FetchedAt),
		in.Label,
		pgtype.Float8{Float64: in.Confidence, Valid: true},
		in.VerdictSource,
		nullableString(in.ModelVersion),
		requiredOrgID(in.OrgID),
	).Scan(&verdictID); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return Output{}, fmt.Errorf("insert verdict: pipeline unique conflict (retry should dedupe): %w", err)
		}
		return Output{}, fmt.Errorf("insert verdict: %w", err)
	}

	// 4. INSERT rule_hits (one per fired rule). Reuse the existing
	// sqlc-generated InsertRuleHit through dbsqlc.New(tx).
	q := dbsqlc.New(tx)
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
			if _, err := tx.Exec(ctx, queryUpdateVerdictKafkaWire, wire, verdictID); err != nil {
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
	var (
		id         int64
		riskScore  pgtype.Int4
		emailCount int32
	)
	err := w.pool.QueryRow(ctx, queryGetCampaignByFingerprint,
		nullableInt8(orgID),
		fingerprint,
	).Scan(&id, &riskScore, &emailCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get campaign by fingerprint: %w", err)
	}
	rs := 0
	if riskScore.Valid {
		rs = int(riskScore.Int32)
	}
	return &CampaignHistory{
		CampaignID: id,
		RiskScore:  rs,
		EmailCount: int(emailCount),
	}, nil
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

func nullableJSONB(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
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
