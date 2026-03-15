package ti

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/repository"
	valkey "github.com/saif/cybersiren/shared/valkey"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Feed interface {
	Name() string
	FeedID() int64
	Fetch(ctx context.Context) ([]TIIndicator, error)
}

type TIIndicator struct {
	FeedID         int64
	IndicatorType  string
	IndicatorValue string
	ThreatType     string
	ThreatTags     []string
	RiskScore      int
	Confidence     float64
	SourceID       string
	RawMetadata    []byte
}

type Runner struct {
	feeds []Feed
	repo  repository.TIRepository
	cache valkey.TICache
	log   zerolog.Logger

	syncTotal    prometheus.Counter
	syncErrors   *prometheus.CounterVec
	syncDuration prometheus.Histogram
}

var runnerTracer = tracing.Tracer("services/svc-11-ti-sync/internal/ti/runner")

func NewRunner(feeds []Feed, repo repository.TIRepository, cache valkey.TICache, log zerolog.Logger, reg *prometheus.Registry) *Runner {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}

	syncTotal := registerCounter(reg, prometheus.NewCounter(prometheus.CounterOpts{
		Name: "feed_sync_total",
		Help: "Total number of successful TI feed sync operations.",
	}))

	syncErrors := registerCounterVec(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "feed_sync_errors_total",
		Help: "Total number of TI feed sync errors partitioned by feed name.",
	}, []string{"feed_name"}))

	syncDuration := registerHistogram(reg, prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "feed_sync_duration_seconds",
		Help:    "Duration of TI feed sync operations in seconds.",
		Buckets: prometheus.DefBuckets,
	}))

	return &Runner{
		feeds:        feeds,
		repo:         repo,
		cache:        cache,
		log:          log,
		syncTotal:    syncTotal,
		syncErrors:   syncErrors,
		syncDuration: syncDuration,
	}
}

func (r *Runner) SyncAll(ctx context.Context) (err error) {
	startedAt := time.Now()
	successCount := 0

	ctx, span := runnerTracer.Start(ctx, "runner.SyncAll")
	defer func() {
		duration := time.Since(startedAt)
		span.SetAttributes(
			attribute.Int("feed_count", len(r.feeds)),
			attribute.Int("success_count", successCount),
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

	if r == nil {
		return errors.New("ti runner is nil")
	}
	if r.repo == nil {
		return errors.New("ti repository is nil")
	}

	for _, feed := range r.feeds {
		if ctx.Err() != nil {
			r.log.Warn().Err(ctx.Err()).Msg("sync context canceled, skipping remaining feeds")
			break
		}

		feedName := feed.Name()
		feedID := feed.FeedID()
		feedCtx, feedSpan := runnerTracer.Start(
			ctx,
			"runner.SyncAll.feed",
			trace.WithAttributes(attribute.String("feed.name", feedName)),
		)

		indicators, fetchErr := feed.Fetch(feedCtx)
		if fetchErr != nil {
			r.log.Error().Err(fetchErr).Str("feed", feedName).Msg("feed fetch failed")
			feedSpan.RecordError(fetchErr)
			feedSpan.SetStatus(codes.Error, fetchErr.Error())
			if r.syncErrors != nil {
				r.syncErrors.WithLabelValues(feedName).Inc()
			}

			r.updateFeedLastFetched(feedCtx, feedName, feedID, feedSpan)
			feedSpan.End()
			continue
		}

		if feedID <= 0 && len(indicators) > 0 {
			feedID = indicators[0].FeedID
		}

		upsertResult, upsertErr := r.repo.BulkUpsertIndicators(feedCtx, toRepositoryIndicators(feedName, feedID, indicators))
		if upsertErr != nil {
			r.log.Error().Err(upsertErr).Str("feed", feedName).Msg("feed indicator upsert failed")
			feedSpan.RecordError(upsertErr)
			feedSpan.SetStatus(codes.Error, upsertErr.Error())
			if r.syncErrors != nil {
				r.syncErrors.WithLabelValues(feedName).Inc()
			}

			r.updateFeedLastFetched(feedCtx, feedName, feedID, feedSpan)
			feedSpan.End()
			continue
		}

		r.log.Info().
			Str("feed", feedName).
			Int("inserted", upsertResult.Inserted).
			Int("updated", upsertResult.Updated).
			Int("deactivated", upsertResult.Deactivated).
			Msg("feed sync completed")

		successCount++
		if r.syncTotal != nil {
			r.syncTotal.Inc()
		}

		r.updateFeedLastFetched(feedCtx, feedName, feedID, feedSpan)
		feedSpan.End()
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	if successCount == 0 && len(r.feeds) > 0 {
		return fmt.Errorf("all %d feeds failed, check logs for individual errors", len(r.feeds))
	}

	if r.cache == nil {
		r.log.Error().Msg("ti cache is nil, skipping domain cache refresh")
	} else if cacheErr := r.cache.RefreshDomainCache(ctx); cacheErr != nil {
		r.log.Error().Err(cacheErr).Msg("failed to refresh TI domain cache")
	}

	if refreshErr := r.repo.RefreshAllMaterializedViews(ctx); refreshErr != nil {
		r.log.Error().Err(refreshErr).Msg("failed to refresh materialized views")
		return refreshErr
	}

	return nil
}

func (r *Runner) Start(ctx context.Context, interval time.Duration) error {
	if interval <= 30*time.Second {
		return fmt.Errorf("sync interval %s too short; must be greater than 30 seconds", interval)
	}

	if err := r.SyncAll(ctx); err != nil {
		r.log.Error().Err(err).Msg("initial TI sync failed")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cycleTimeout := interval * 9 / 10
	var cycleRunning atomic.Bool
	var wg sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			r.log.Info().Msg("runner shutting down, waiting for active sync to finish")
			wg.Wait()
			return nil
		case <-ticker.C:
			if !cycleRunning.CompareAndSwap(false, true) {
				r.log.Warn().Msg("previous sync cycle still running, skipping tick")
				continue
			}

			cycleCtx, cancel := context.WithTimeout(ctx, cycleTimeout)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer cycleRunning.Store(false)
				defer cancel()

				if err := r.SyncAll(cycleCtx); err != nil {
					r.log.Error().Err(err).Msg("scheduled TI sync failed")
				}
			}()
		}
	}
}

func (r *Runner) updateFeedLastFetched(ctx context.Context, feedName string, feedID int64, span trace.Span) {
	updateErr := r.repo.UpdateFeedLastFetched(ctx, feedID)
	if updateErr == nil {
		return
	}

	r.log.Error().
		Err(updateErr).
		Str("feed", feedName).
		Int64("feed_id", feedID).
		Msg("failed to update feed last fetched timestamp")

	if span != nil {
		span.RecordError(updateErr)
		span.SetStatus(codes.Error, updateErr.Error())
	}
}

func toRepositoryIndicators(feedName string, fallbackFeedID int64, indicators []TIIndicator) []repository.TIIndicator {
	if len(indicators) == 0 {
		return []repository.TIIndicator{}
	}

	converted := make([]repository.TIIndicator, 0, len(indicators))
	for _, indicator := range indicators {
		feedID := indicator.FeedID
		if feedID <= 0 {
			feedID = fallbackFeedID
		}

		confidence := indicator.Confidence

		converted = append(converted, repository.TIIndicator{
			FeedID:         feedID,
			FeedName:       feedName,
			IndicatorType:  db.TiIndicatorType(strings.TrimSpace(indicator.IndicatorType)),
			IndicatorValue: strings.TrimSpace(indicator.IndicatorValue),
			ThreatType:     strings.TrimSpace(indicator.ThreatType),
			ThreatTags:     append([]string(nil), indicator.ThreatTags...),
			SourceID:       strings.TrimSpace(indicator.SourceID),
			Confidence:     &confidence,
			RiskScore:      indicator.RiskScore,
			RawMetadata:    append([]byte(nil), indicator.RawMetadata...),
		})
	}

	return converted
}

func registerCounter(registry *prometheus.Registry, counter prometheus.Counter) prometheus.Counter {
	err := registry.Register(counter)
	if err == nil {
		return counter
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Counter)
		if ok {
			return existing
		}
	}

	return counter
}

func registerCounterVec(registry *prometheus.Registry, counterVec *prometheus.CounterVec) *prometheus.CounterVec {
	err := registry.Register(counterVec)
	if err == nil {
		return counterVec
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if ok {
			return existing
		}
	}

	return counterVec
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
