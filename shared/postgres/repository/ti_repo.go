package repository

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/observability/tracing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const indicatorChunkSize = 500

var tiRepoTracer = tracing.Tracer("shared/postgres/repository/ti_repo")

// TIRepository is the interface all callers should use.
type TIRepository interface {
	BulkUpsertIndicators(ctx context.Context, indicators []TIIndicator) (UpsertResult, error)
	BulkUpsertMalwareHashes(ctx context.Context, hashes []MalwareHash) (UpsertResult, error)
	DeactivateStaleIndicators(ctx context.Context, feedID int64) (int, error)
	UpdateFeedLastFetched(ctx context.Context, feedID int64) error
	ListActiveDomainIndicators(ctx context.Context) ([]DomainIndicator, error)
	ListMaliciousHashes(ctx context.Context) ([]MaliciousHash, error)
	RefreshAllMaterializedViews(ctx context.Context) error
}

// TIIndicator is the repository input model for TI upsert operations.
type TIIndicator struct {
	FeedID         int64
	FeedName       string
	IndicatorType  db.TiIndicatorType
	IndicatorValue string
	ThreatType     string
	BrandID        *int64
	TargetBrand    string
	ThreatTags     []string
	SourceID       string
	FirstSeen      time.Time
	LastSeen       time.Time
	Confidence     *float64
	RiskScore      int
	RawMetadata    []byte
}

type UpsertResult struct {
	Inserted    int
	Updated     int
	Deactivated int
}

// DomainIndicator is the repository output model for active domain indicators.
type DomainIndicator struct {
	ID             int64
	IndicatorValue string
	ThreatType     string
	RiskScore      int
}

// MalwareHash is the repository input model for malware hash upsert operations.
type MalwareHash struct {
	SHA256     string
	RiskScore  int
	ThreatTags []string
}

// MaliciousHash is the repository output model for known-malicious attachment hashes.
type MaliciousHash struct {
	ID         int64
	SHA256     string
	RiskScore  int
	ThreatTags []string
	UpdatedAt  time.Time
}

// PostgresTIRepository is the concrete pgx-backed implementation.
type PostgresTIRepository struct {
	pool         *pgxpool.Pool
	q            *db.Queries
	log          zerolog.Logger
	upsertTotal  *prometheus.CounterVec
	syncDuration prometheus.Histogram
}

// Compile-time interface check.
var _ TIRepository = (*PostgresTIRepository)(nil)

func NewTIRepository(pool *pgxpool.Pool, log zerolog.Logger, metrics *prometheus.Registry) *PostgresTIRepository {
	if metrics == nil {
		metrics = prometheus.NewRegistry()
	}

	upsertTotal := registerCounterVec(metrics, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "feed_sync_upsert_total",
			Help: "Total TI feed indicator upsert outcomes partitioned by feed and result type.",
		},
		[]string{"feed_name", "result"},
	))

	syncDuration := registerHistogram(metrics, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "feed_sync_db_upsert_duration_seconds",
			Help:    "Duration of TI indicator DB upsert transactions in seconds.",
			Buckets: prometheus.DefBuckets,
		},
	))

	r := &PostgresTIRepository{
		pool:         pool,
		log:          log,
		upsertTotal:  upsertTotal,
		syncDuration: syncDuration,
	}

	if pool != nil {
		r.q = db.New(pool)
	}

	return r
}

func (r *PostgresTIRepository) BulkUpsertIndicators(ctx context.Context, indicators []TIIndicator) (result UpsertResult, err error) {
	startedAt := time.Now().UTC()
	feedID := int64(0)

	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.BulkUpsertIndicators")
	defer func() {
		duration := time.Since(startedAt)
		span.SetAttributes(
			attribute.Int64("feed_id", feedID),
			attribute.Int("indicator_count", len(indicators)),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)

		if r != nil && r.syncDuration != nil {
			r.syncDuration.Observe(duration.Seconds())
		}

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}

		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return result, err
	}

	if len(indicators) == 0 {
		return result, nil
	}

	feedID = indicators[0].FeedID
	if feedID <= 0 {
		return result, fmt.Errorf("invalid feed_id in batch: %d", feedID)
	}

	feedName := feedLabel(feedID, indicators[0].FeedName)

	tx, txErr := r.pool.Begin(ctx)
	if txErr != nil {
		return result, fmt.Errorf("begin ti upsert transaction: %w", txErr)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := r.q.WithTx(tx)

	for chunkStart := 0; chunkStart < len(indicators); chunkStart += indicatorChunkSize {
		chunkEnd := chunkStart + indicatorChunkSize
		if chunkEnd > len(indicators) {
			chunkEnd = len(indicators)
		}

		for _, indicator := range indicators[chunkStart:chunkEnd] {
			if indicator.FeedID != feedID {
				return result, fmt.Errorf("mixed feed ids in batch: expected %d, got %d", feedID, indicator.FeedID)
			}

			params, convErr := toUpsertParams(indicator, startedAt)
			if convErr != nil {
				return result, convErr
			}

			wasInserted, upsertErr := qtx.UpsertTIIndicator(ctx, params)
			if upsertErr != nil {
				return result, fmt.Errorf("upsert ti indicator %q: %w", indicator.IndicatorValue, upsertErr)
			}

			if wasInserted {
				result.Inserted++
			} else {
				result.Updated++
			}
		}
	}

	deactivated, deactivateErr := qtx.DeactivateStaleFeedIndicators(ctx, db.DeactivateStaleFeedIndicatorsParams{
		FeedID: feedID,
		LastSeen: pgtype.Timestamptz{
			Time:  startedAt,
			Valid: true,
		},
	})
	if deactivateErr != nil {
		return result, fmt.Errorf("deactivate stale indicators for feed %d: %w", feedID, deactivateErr)
	}
	result.Deactivated = int(deactivated)

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return result, fmt.Errorf("commit ti upsert transaction: %w", commitErr)
	}

	r.observeUpsertMetrics(feedName, result)
	span.SetAttributes(
		attribute.Int("inserted", result.Inserted),
		attribute.Int("updated", result.Updated),
		attribute.Int("deactivated", result.Deactivated),
	)

	return result, nil
}

// DeactivateStaleIndicators marks indicators for the given feed as inactive
// when their last_seen timestamp is older than the current sync run.
func (r *PostgresTIRepository) DeactivateStaleIndicators(ctx context.Context, feedID int64) (deactivated int, err error) {
	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.DeactivateStaleIndicators")
	defer func() {
		span.SetAttributes(
			attribute.Int64("feed_id", feedID),
			attribute.Int("deactivated", deactivated),
		)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return 0, err
	}

	count, deactivateErr := r.q.DeactivateStaleFeedIndicators(ctx, db.DeactivateStaleFeedIndicatorsParams{
		FeedID: feedID,
		LastSeen: pgtype.Timestamptz{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	})
	if deactivateErr != nil {
		return 0, fmt.Errorf("deactivate stale indicators for feed %d: %w", feedID, deactivateErr)
	}

	return int(count), nil
}

func (r *PostgresTIRepository) UpdateFeedLastFetched(ctx context.Context, feedID int64) (err error) {
	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.UpdateFeedLastFetched")
	defer func() {
		span.SetAttributes(attribute.Int64("feed_id", feedID))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return err
	}

	if err = r.q.UpdateFeedLastFetched(ctx, feedID); err != nil {
		return fmt.Errorf("update feed last fetched for feed %d: %w", feedID, err)
	}

	return nil
}

func (r *PostgresTIRepository) ListActiveDomainIndicators(ctx context.Context) (items []DomainIndicator, err error) {
	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.ListActiveDomainIndicators")
	defer func() {
		span.SetAttributes(attribute.Int("indicator_count", len(items)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return nil, err
	}

	rows, queryErr := r.q.ListActiveDomainIndicators(ctx)
	if queryErr != nil {
		return nil, fmt.Errorf("list active domain indicators: %w", queryErr)
	}

	items = make([]DomainIndicator, 0, len(rows))
	for _, row := range rows {
		threatType := ""
		if row.ThreatType.Valid {
			threatType = row.ThreatType.String
		}

		items = append(items, DomainIndicator{
			ID:             row.ID,
			IndicatorValue: row.IndicatorValue,
			RiskScore:      int(row.RiskScore),
			ThreatType:     threatType,
		})
	}

	return items, nil
}

func (r *PostgresTIRepository) BulkUpsertMalwareHashes(ctx context.Context, hashes []MalwareHash) (result UpsertResult, err error) {
	startedAt := time.Now().UTC()

	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.BulkUpsertMalwareHashes")
	defer func() {
		duration := time.Since(startedAt)
		span.SetAttributes(
			attribute.Int("hash_count", len(hashes)),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)

		if r != nil && r.syncDuration != nil {
			r.syncDuration.Observe(duration.Seconds())
		}

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}

		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return result, err
	}

	if len(hashes) == 0 {
		return result, nil
	}

	tx, txErr := r.pool.Begin(ctx)
	if txErr != nil {
		return result, fmt.Errorf("begin malware hash upsert transaction: %w", txErr)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := r.q.WithTx(tx)

	for chunkStart := 0; chunkStart < len(hashes); chunkStart += indicatorChunkSize {
		chunkEnd := chunkStart + indicatorChunkSize
		if chunkEnd > len(hashes) {
			chunkEnd = len(hashes)
		}

		for _, h := range hashes[chunkStart:chunkEnd] {
			sha := strings.TrimSpace(strings.ToLower(h.SHA256))
			if sha == "" {
				continue
			}

			if !normalization.IsValidHexHash(sha, 64) {
				r.log.Warn().Str("sha256", sha).Msg("skipping invalid SHA-256 hash in bulk upsert")
				continue
			}

			riskScore := h.RiskScore
			if riskScore < 0 || riskScore > 100 {
				return result, fmt.Errorf("malware hash %q: risk_score must be between 0 and 100, got %d", sha, riskScore)
			}

			tags := append([]string(nil), h.ThreatTags...)
			if tags == nil {
				tags = []string{}
			}

			upsertErr := qtx.UpsertMalwareHash(ctx, db.UpsertMalwareHashParams{
				Sha256: sha,
				RiskScore: pgtype.Int4{
					Int32: int32(riskScore),
					Valid: true,
				},
				ThreatTags: tags,
			})
			if upsertErr != nil {
				return result, fmt.Errorf("upsert malware hash %q: %w", sha, upsertErr)
			}

			// UpsertMalwareHash is :exec so we cannot distinguish insert vs update.
			// Count every row as inserted for observability purposes.
			result.Inserted++
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return result, fmt.Errorf("commit malware hash upsert transaction: %w", commitErr)
	}

	r.observeUpsertMetrics("malware_hashes", result)
	span.SetAttributes(
		attribute.Int("inserted", result.Inserted),
	)

	return result, nil
}

func (r *PostgresTIRepository) ListMaliciousHashes(ctx context.Context) (items []MaliciousHash, err error) {
	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.ListMaliciousHashes")
	defer func() {
		span.SetAttributes(attribute.Int("hash_count", len(items)))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return nil, err
	}

	rows, queryErr := r.q.ListMaliciousHashes(ctx)
	if queryErr != nil {
		return nil, fmt.Errorf("list malicious hashes: %w", queryErr)
	}

	items = make([]MaliciousHash, 0, len(rows))
	for _, row := range rows {
		riskScore := 0
		if row.RiskScore.Valid {
			riskScore = int(row.RiskScore.Int32)
		}

		tags := row.ThreatTags
		if tags == nil {
			tags = []string{}
		}

		updatedAt := time.Time{}
		if row.UpdatedAt.Valid {
			updatedAt = row.UpdatedAt.Time.UTC()
		}

		items = append(items, MaliciousHash{
			ID:         row.ID,
			SHA256:     row.Sha256,
			RiskScore:  riskScore,
			ThreatTags: tags,
			UpdatedAt:  updatedAt,
		})
	}

	return items, nil
}

func (r *PostgresTIRepository) RefreshAllMaterializedViews(ctx context.Context) (err error) {
	startedAt := time.Now()

	ctx, span := tiRepoTracer.Start(ctx, "ti_repo.RefreshAllMaterializedViews")
	defer func() {
		span.SetAttributes(attribute.Float64("duration_seconds", time.Since(startedAt).Seconds()))
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = r.ensureReady(); err != nil {
		return err
	}

	r.log.Info().Msg("refreshing all materialized views")

	if _, execErr := r.pool.Exec(ctx, "SELECT refresh_all_materialized_views()"); execErr != nil {
		return fmt.Errorf("refresh all materialized views: %w", execErr)
	}

	r.log.Info().Dur("duration", time.Since(startedAt)).Msg("refreshed all materialized views")
	return nil
}

func (r *PostgresTIRepository) ensureReady() error {
	if r == nil {
		return errors.New("ti repository is nil")
	}
	if r.pool == nil {
		return errors.New("postgres pool is nil")
	}
	if r.q == nil {
		return errors.New("sqlc queries are not initialized")
	}
	return nil
}

func (r *PostgresTIRepository) observeUpsertMetrics(feedName string, result UpsertResult) {
	if r == nil || r.upsertTotal == nil {
		return
	}

	if result.Inserted > 0 {
		r.upsertTotal.WithLabelValues(feedName, "inserted").Add(float64(result.Inserted))
	}
	if result.Updated > 0 {
		r.upsertTotal.WithLabelValues(feedName, "updated").Add(float64(result.Updated))
	}
	if result.Deactivated > 0 {
		r.upsertTotal.WithLabelValues(feedName, "deactivated").Add(float64(result.Deactivated))
	}
}

func toUpsertParams(indicator TIIndicator, defaultSeen time.Time) (db.UpsertTIIndicatorParams, error) {
	if indicator.FeedID <= 0 {
		return db.UpsertTIIndicatorParams{}, fmt.Errorf("invalid indicator feed_id: %d", indicator.FeedID)
	}

	if strings.TrimSpace(string(indicator.IndicatorType)) == "" {
		return db.UpsertTIIndicatorParams{}, errors.New("indicator_type is required")
	}

	indicatorValue, normErr := normalizeIndicatorValue(indicator.IndicatorType, indicator.IndicatorValue)
	if normErr != nil {
		return db.UpsertTIIndicatorParams{}, fmt.Errorf("normalize indicator_value: %w", normErr)
	}

	if indicator.RiskScore < 0 || indicator.RiskScore > 100 {
		return db.UpsertTIIndicatorParams{}, fmt.Errorf("risk_score must be between 0 and 100, got %d", indicator.RiskScore)
	}

	firstSeen := indicator.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = defaultSeen
	}

	lastSeen := indicator.LastSeen
	if lastSeen.IsZero() {
		lastSeen = defaultSeen
	}

	params := db.UpsertTIIndicatorParams{
		FeedID:         indicator.FeedID,
		IndicatorType:  indicator.IndicatorType,
		IndicatorValue: indicatorValue,
		ThreatType:     nullableText(indicator.ThreatType),
		BrandID:        nullableInt8(indicator.BrandID),
		TargetBrand:    nullableText(indicator.TargetBrand),
		ThreatTags:     append([]string(nil), indicator.ThreatTags...),
		SourceID:       nullableText(indicator.SourceID),
		FirstSeen: pgtype.Timestamptz{
			Time:  firstSeen.UTC(),
			Valid: true,
		},
		LastSeen: pgtype.Timestamptz{
			Time:  lastSeen.UTC(),
			Valid: true,
		},
		Confidence:  nullableFloat8(indicator.Confidence),
		RiskScore:   int32(indicator.RiskScore),
		IsActive:    true,
		RawMetadata: append([]byte(nil), indicator.RawMetadata...),
	}

	if params.ThreatTags == nil {
		params.ThreatTags = []string{}
	}

	return params, nil
}

// normalizeIndicatorValue returns a canonical form of value for the given
// indicator type, preventing duplicates caused by casing, trailing dots,
// wildcard prefixes, or non-canonical IP/CIDR representations.
func normalizeIndicatorValue(itype db.TiIndicatorType, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", errors.New("indicator_value is required")
	}

	switch itype {
	case db.TiIndicatorTypeUrl:
		norm, err := normalization.NormalizeURL(v)
		if err != nil {
			return "", fmt.Errorf("invalid url %q: %w", v, err)
		}
		return norm, nil

	case db.TiIndicatorTypeDomain:
		return normalization.NormalizeDomain(v), nil

	case db.TiIndicatorTypeIp:
		ip := net.ParseIP(v)
		if ip == nil {
			return "", fmt.Errorf("invalid ip address %q", v)
		}
		return ip.String(), nil

	case db.TiIndicatorTypeCidr:
		_, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			return "", fmt.Errorf("invalid cidr %q: %w", v, err)
		}
		return ipNet.String(), nil

	case db.TiIndicatorTypeHash:
		return strings.ToLower(v), nil

	case db.TiIndicatorTypeEmailAddress:
		return strings.ToLower(v), nil

	default:
		// Unknown future type: return trimmed value as-is.
		return v, nil
	}
}

func nullableText(value string) pgtype.Text {
	value = strings.TrimSpace(value)
	if value == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: value, Valid: true}
}

func nullableInt8(value *int64) pgtype.Int8 {
	if value == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *value, Valid: true}
}

func nullableFloat8(value *float64) pgtype.Float8 {
	if value == nil {
		return pgtype.Float8{}
	}
	return pgtype.Float8{Float64: *value, Valid: true}
}

func feedLabel(feedID int64, feedName string) string {
	feedName = strings.TrimSpace(feedName)
	if feedName != "" {
		return feedName
	}
	return strconv.FormatInt(feedID, 10)
}

func registerCounterVec(registry *prometheus.Registry, counter *prometheus.CounterVec) *prometheus.CounterVec {
	err := registry.Register(counter)
	if err == nil {
		return counter
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if ok {
			return existing
		}
	}

	return counter
}

func registerHistogram(registry *prometheus.Registry, histogram prometheus.Histogram) prometheus.Histogram {
	err := registry.Register(histogram)
	if err == nil {
		return histogram
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Histogram)
		if ok {
			return existing
		}
	}

	return histogram
}
