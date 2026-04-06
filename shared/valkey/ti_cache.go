package valkey

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

const (
	tiDomainTTLSeconds   int64 = 3600
	tiDomainRefreshBatch       = 200
)

var tiCacheTracer = tracing.Tracer("shared/valkey/ti_cache")

// TICache provides read and write access to the threat-intelligence domain cache.
type TICache interface {
	RefreshDomainCache(ctx context.Context) error
	// IsBlocklisted checks whether the given domain appears in the TI domain cache.
	IsBlocklisted(ctx context.Context, domain string) (bool, int, string, error)
}

type ValkeyTICache struct {
	client valkeygo.Client
	repo   repository.TIRepository
	log    zerolog.Logger

	refreshKeysTotal prometheus.Gauge
	refreshDuration  prometheus.Histogram
	blocklistLookups *prometheus.CounterVec
}

var _ TICache = (*ValkeyTICache)(nil)

func NewTICache(client valkeygo.Client, repo repository.TIRepository, log zerolog.Logger, metrics *prometheus.Registry) *ValkeyTICache {
	if metrics == nil {
		metrics = prometheus.NewRegistry()
	}

	refreshKeysTotal := registerGauge(metrics, prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ti_cache_refresh_keys_total",
		Help: "Total TI domain cache keys written in the most recent refresh.",
	}))

	refreshDuration := registerHistogram(metrics, prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ti_cache_refresh_duration_seconds",
		Help:    "Duration of TI domain cache refresh operations in seconds.",
		Buckets: prometheus.DefBuckets,
	}))

	blocklistLookups := registerCounterVec(metrics, prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ti_cache_blocklist_lookups_total",
		Help: "Total blocklist lookups against the TI domain cache.",
	}, []string{"hit"}))

	return &ValkeyTICache{
		client:           client,
		repo:             repo,
		log:              log,
		refreshKeysTotal: refreshKeysTotal,
		refreshDuration:  refreshDuration,
		blocklistLookups: blocklistLookups,
	}
}

func (c *ValkeyTICache) RefreshDomainCache(ctx context.Context) (err error) {
	startedAt := time.Now()
	keysWritten := 0
	commandErrors := 0

	ctx, span := tiCacheTracer.Start(ctx, "ti_cache.RefreshDomainCache")
	defer func() {
		duration := time.Since(startedAt)
		span.SetAttributes(
			attribute.Int("keys_written", keysWritten),
			attribute.Int("command_errors", commandErrors),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)

		if c != nil && c.refreshDuration != nil {
			c.refreshDuration.Observe(duration.Seconds())
		}

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if err = c.ensureReady(); err != nil {
		return err
	}

	domainIndicators, listErr := c.repo.ListActiveDomainIndicators(ctx)
	if listErr != nil {
		return fmt.Errorf("list active domain indicators: %w", listErr)
	}

	for start := 0; start < len(domainIndicators); start += tiDomainRefreshBatch {
		end := start + tiDomainRefreshBatch
		if end > len(domainIndicators) {
			end = len(domainIndicators)
		}

		chunk := domainIndicators[start:end]
		cmds := make([]valkeygo.Completed, 0, len(chunk)*2)
		metas := make([]cacheCommandMeta, 0, len(chunk)*2)
		keyStates := make([]cacheKeyState, 0, len(chunk))

		for _, indicator := range chunk {
			domain := strings.TrimSpace(indicator.IndicatorValue)
			if domain == "" {
				c.log.Warn().
					Int64("ti_indicator_id", indicator.ID).
					Msg("skipping TI domain indicator with empty value")
				continue
			}

			key := fmt.Sprintf("ti_domain:{%s}", domain)
			hsetCmd := c.client.B().Hset().
				Key(key).
				FieldValue().
				FieldValue("ti_indicator_id", strconv.FormatInt(indicator.ID, 10)).
				FieldValue("risk_score", strconv.Itoa(indicator.RiskScore)).
				FieldValue("threat_type", indicator.ThreatType).
				Build()
			expireCmd := c.client.B().Expire().Key(key).Seconds(tiDomainTTLSeconds).Build()

			cmds = append(cmds, hsetCmd, expireCmd)
			metas = append(metas,
				cacheCommandMeta{Key: key, Command: "HSET"},
				cacheCommandMeta{Key: key, Command: "EXPIRE"},
			)
			keyStates = append(keyStates, cacheKeyState{})
		}

		if len(cmds) == 0 {
			continue
		}

		results := c.client.DoMulti(ctx, cmds...)
		if len(results) != len(metas) {
			c.log.Error().
				Int("cmd_count", len(metas)).
				Int("result_count", len(results)).
				Msg("valkey DoMulti returned unexpected result count")
		}

		limit := len(results)
		if limit > len(metas) {
			limit = len(metas)
		}

		for i := 0; i < limit; i++ {
			resultErr := results[i].Error()
			if resultErr != nil {
				commandErrors++
				meta := metas[i]
				c.log.Error().
					Err(resultErr).
					Str("key", meta.Key).
					Str("command", meta.Command).
					Msg("failed TI domain cache command")
				continue
			}

			keyIndex := i / 2
			if keyIndex >= len(keyStates) {
				continue
			}
			if i%2 == 0 {
				keyStates[keyIndex].HSetOK = true
			} else {
				keyStates[keyIndex].ExpireOK = true
			}
		}

		for i := limit; i < len(metas); i++ {
			commandErrors++
			meta := metas[i]
			c.log.Error().
				Str("key", meta.Key).
				Str("command", meta.Command).
				Msg("missing TI domain cache command result")
		}

		for _, keyState := range keyStates {
			if keyState.HSetOK && keyState.ExpireOK {
				keysWritten++
			}
		}
	}

	if c.refreshKeysTotal != nil {
		c.refreshKeysTotal.Set(float64(keysWritten))
	}

	return nil
}

// IsBlocklisted checks whether the given domain appears in the TI domain cache.
func (c *ValkeyTICache) IsBlocklisted(ctx context.Context, domain string) (blocked bool, riskScore int, threatType string, err error) {
	ctx, span := tiCacheTracer.Start(ctx, "ti_cache.IsBlocklisted")
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	normalized := normalization.NormalizeDomain(domain)
	key := fmt.Sprintf("ti_domain:{%s}", normalized)

	span.SetAttributes(attribute.String("domain", normalized))

	cmd := c.client.Do(ctx, c.client.B().Hgetall().Key(key).Build())
	if err = cmd.Error(); err != nil {
		return false, 0, "", fmt.Errorf("ti cache IsBlocklisted: %w", err)
	}

	result, err := cmd.AsStrMap()
	if err != nil {
		return false, 0, "", fmt.Errorf("ti cache IsBlocklisted: %w", err)
	}

	hit := len(result) > 0
	if c.blocklistLookups != nil {
		c.blocklistLookups.WithLabelValues(strconv.FormatBool(hit)).Inc()
	}

	if !hit {
		return false, 0, "", nil
	}

	if scoreStr, ok := result["risk_score"]; ok {
		riskScore, err = strconv.Atoi(scoreStr)
		if err != nil {
			return false, 0, "", fmt.Errorf("ti cache IsBlocklisted: parse risk_score: %w", err)
		}
	}
	threatType = result["threat_type"]

	return true, riskScore, threatType, nil
}

func (c *ValkeyTICache) ensureReady() error {
	if c == nil {
		return errors.New("ti cache is nil")
	}
	if c.client == nil {
		return errors.New("valkey client is nil")
	}
	if c.repo == nil {
		return errors.New("ti repository is nil")
	}
	return nil
}

type cacheCommandMeta struct {
	Key     string
	Command string
}

type cacheKeyState struct {
	HSetOK   bool
	ExpireOK bool
}

func registerGauge(registry *prometheus.Registry, gauge prometheus.Gauge) prometheus.Gauge {
	err := registry.Register(gauge)
	if err == nil {
		return gauge
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Gauge)
		if ok {
			return existing
		}
	}

	return gauge
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
