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
	// tiDomainTTLDefaultSeconds is used when NewTICache is given a non-positive
	// TTL. It is twice the default sync interval so domain keys survive the gap
	// between the end of one refresh and the next (see config.Validate, which
	// guards ti_domain_cache_ttl_seconds >= sync_interval_seconds).
	tiDomainTTLDefaultSeconds int64 = 7200
	tiDomainRefreshBatch            = 200
)

var tiCacheTracer = tracing.Tracer("shared/valkey/ti_cache")

// DomainLookup is the result of a TI domain cache lookup. It carries the
// matched ti_indicators.id (IndicatorID) so callers that audit feed matches
// (e.g. svc-03's email_url_ti_matches writer) can attribute the hit. Legacy
// cache entries written before the id was stored leave IndicatorID at zero.
type DomainLookup struct {
	Blocked     bool
	RiskScore   int
	ThreatType  string
	IndicatorID int64
}

// TICache provides read and write access to the threat-intelligence caches.
type TICache interface {
	RefreshDomainCache(ctx context.Context) error
	// IsBlocklisted checks whether the given domain appears in the TI domain cache.
	IsBlocklisted(ctx context.Context, domain string) (bool, int, string, error)
	// LookupDomain is the richer variant of IsBlocklisted: it returns the same
	// blocked/risk/threat signal plus the matched ti_indicators.id so callers
	// can audit the feed match.
	LookupDomain(ctx context.Context, domain string) (DomainLookup, error)
}

type ValkeyTICache struct {
	client           valkeygo.Client
	repo             repository.TIRepository
	log              zerolog.Logger
	domainTTLSeconds int64

	refreshKeysTotal *prometheus.GaugeVec
	refreshDuration  *prometheus.HistogramVec
	blocklistLookups *prometheus.CounterVec
}

var _ TICache = (*ValkeyTICache)(nil)

func NewTICache(
	client valkeygo.Client,
	repo repository.TIRepository,
	log zerolog.Logger,
	metrics *prometheus.Registry,
	domainTTLSeconds int64,
) *ValkeyTICache {
	if metrics == nil {
		metrics = prometheus.NewRegistry()
	}

	refreshKeysTotal := registerGaugeVec(metrics, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ti_cache_refresh_keys_total",
		Help: "Total TI cache keys written in the most recent refresh, partitioned by cache type.",
	}, []string{"cache_type"}))

	refreshDuration := registerHistogramVec(metrics, prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ti_cache_refresh_duration_seconds",
		Help:    "Duration of TI cache refresh operations in seconds, partitioned by cache type.",
		Buckets: prometheus.DefBuckets,
	}, []string{"cache_type"}))

	blocklistLookups := registerCounterVec(metrics, prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ti_cache_blocklist_lookups_total",
		Help: "Total blocklist lookups against the TI domain cache.",
	}, []string{"hit"}))

	if domainTTLSeconds <= 0 {
		domainTTLSeconds = tiDomainTTLDefaultSeconds
	}

	return &ValkeyTICache{
		client:           client,
		repo:             repo,
		log:              log,
		domainTTLSeconds: domainTTLSeconds,
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

		c.observeRefreshDuration("domain", duration)

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
			expireCmd := c.client.B().Expire().Key(key).Seconds(c.domainTTLSeconds).Build()

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

	c.setRefreshKeys("domain", keysWritten)

	return nil
}

// IsBlocklisted checks whether the given domain appears in the TI domain cache.
// It is the back-compat shim over LookupDomain for callers that do not need the
// matched ti_indicators.id.
func (c *ValkeyTICache) IsBlocklisted(ctx context.Context, domain string) (bool, int, string, error) {
	res, err := c.LookupDomain(ctx, domain)
	if err != nil {
		return false, 0, "", err
	}
	return res.Blocked, res.RiskScore, res.ThreatType, nil
}

// LookupDomain checks whether the given domain appears in the TI domain cache,
// returning the blocked/risk/threat signal plus the matched ti_indicators.id.
// A legacy cache entry written before the id field was stored leaves
// IndicatorID at zero (the caller's audit then skips, as before).
func (c *ValkeyTICache) LookupDomain(ctx context.Context, domain string) (lookup DomainLookup, err error) {
	ctx, span := tiCacheTracer.Start(ctx, "ti_cache.LookupDomain")
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
		return DomainLookup{}, fmt.Errorf("ti cache LookupDomain: %w", err)
	}

	result, mapErr := cmd.AsStrMap()
	if mapErr != nil {
		err = fmt.Errorf("ti cache LookupDomain: %w", mapErr)
		return DomainLookup{}, err
	}

	hit := len(result) > 0
	if c.blocklistLookups != nil {
		c.blocklistLookups.WithLabelValues(strconv.FormatBool(hit)).Inc()
	}

	if !hit {
		return DomainLookup{}, nil
	}

	out := DomainLookup{Blocked: true, ThreatType: result["threat_type"]}

	if scoreStr, ok := result["risk_score"]; ok {
		out.RiskScore, err = strconv.Atoi(scoreStr)
		if err != nil {
			return DomainLookup{}, fmt.Errorf("ti cache LookupDomain: parse risk_score: %w", err)
		}
	}
	if idStr, ok := result["ti_indicator_id"]; ok && idStr != "" {
		out.IndicatorID, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return DomainLookup{}, fmt.Errorf("ti cache LookupDomain: parse ti_indicator_id: %w", err)
		}
	}

	return out, nil
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

func registerGaugeVec(registry *prometheus.Registry, gaugeVec *prometheus.GaugeVec) *prometheus.GaugeVec {
	err := registry.Register(gaugeVec)
	if err == nil {
		return gaugeVec
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.GaugeVec)
		if ok {
			return existing
		}
	}

	return gaugeVec
}

func registerHistogramVec(registry *prometheus.Registry, histogramVec *prometheus.HistogramVec) *prometheus.HistogramVec {
	err := registry.Register(histogramVec)
	if err == nil {
		return histogramVec
	}

	var alreadyRegistered prometheus.AlreadyRegisteredError
	if errors.As(err, &alreadyRegistered) {
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.HistogramVec)
		if ok {
			return existing
		}
	}

	return histogramVec
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

// observeRefreshDuration records TI cache refresh latency for the given cache type.
func (c *ValkeyTICache) observeRefreshDuration(cacheType string, duration time.Duration) {
	if c == nil || c.refreshDuration == nil {
		return
	}

	c.refreshDuration.WithLabelValues(cacheType).Observe(duration.Seconds())
}

// setRefreshKeys records the latest successful TI cache refresh key count for the given cache type.
func (c *ValkeyTICache) setRefreshKeys(cacheType string, keysWritten int) {
	if c == nil || c.refreshKeysTotal == nil {
		return
	}

	c.refreshKeysTotal.WithLabelValues(cacheType).Set(float64(keysWritten))
}
