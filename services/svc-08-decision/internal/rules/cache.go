// Package rules provides the rule cache and evaluator for SVC-08
// Decision Engine. The DSL itself is reused from
// services/svc-04-header-analysis/internal/rules — we wrap rather than
// duplicate so the JSON-DSL interpreter stays single-sourced.
//
// The cache is a behavioural twin of svc-04's: three tiers (in-memory →
// Valkey → Postgres), 60-second TTL, periodic refresh. Metric names use
// the `decision_` prefix to avoid Prometheus registration collisions.
//
// See docs/design/svc-07-08-design-brief.md §3.5 and §C.6/C.7.
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/rules/dsl"
)

// CachedRule is the SVC-08 rule view; aliased to the shared DSL type
// so the engine, the rule cache, and svc-04 all agree on the rule
// shape without conversion.
type CachedRule = dsl.CachedRule

// FiredRule mirrors the shared DSL FiredRule for the same reason.
type FiredRule = dsl.FiredRule

// SignalSnapshot is the flat key→value view the DSL evaluates against.
type SignalSnapshot = dsl.SignalSnapshot

// CacheConfig configures Cache behaviour. Defaults are appropriate for
// the SVC-08 decision engine (60-second TTL).
//
// Targets: Postgres rule_target_enum has email|url|attachment|header|campaign
// — there is no "decision" value. svc-08 loads rules that fire on email-level
// and campaign-level snapshots (overlap with svc-04 only on target=email rules;
// svc-04 also loads header + email — keep products' Valkey caches distinct).
type CacheConfig struct {
	// Targets is the set of rules.target values to load. Defaults to
	// {"email", "campaign"}.
	Targets []string
	// TTL controls in-memory + Valkey cache expiry. ARCH-SPEC §5
	// mandates 60s.
	TTL time.Duration
}

// Cache is a near-verbatim copy of svc-04's three-tier rule cache,
// with the metric prefix adjusted from `header_rule_cache_*` to
// `decision_rule_cache_*` to avoid Prometheus registration conflicts
// when both services share an HTTP exposition port.
type Cache struct {
	pool    *pgxpool.Pool
	queries *dbsqlc.Queries
	valkey  valkeygo.Client
	log     zerolog.Logger
	ttl     time.Duration
	targets []string

	mu        sync.RWMutex
	entries   map[int64]*atomic.Value
	knownOrgs map[int64]struct{}

	cacheHits   *prometheus.CounterVec
	cacheMisses *prometheus.CounterVec
	loadErrors  *prometheus.CounterVec
	rulesLoaded *prometheus.GaugeVec
}

type cacheEntry struct {
	rules    []CachedRule
	loadedAt time.Time
}

// NewCache constructs a Cache. valkey may be nil to skip the
// cross-instance warm cache.
func NewCache(
	pool *pgxpool.Pool,
	valkey valkeygo.Client,
	cfg CacheConfig,
	log zerolog.Logger,
	reg *prometheus.Registry,
) *Cache {
	if cfg.TTL <= 0 {
		cfg.TTL = 60 * time.Second
	}
	if len(cfg.Targets) == 0 {
		cfg.Targets = []string{"email", "campaign"}
	}

	c := &Cache{
		pool:      pool,
		queries:   dbsqlc.New(pool),
		valkey:    valkey,
		log:       log,
		ttl:       cfg.TTL,
		targets:   cfg.Targets,
		entries:   make(map[int64]*atomic.Value),
		knownOrgs: make(map[int64]struct{}),
	}

	if reg != nil {
		c.cacheHits = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "decision_rule_cache_hits_total",
				Help: "Total rule-cache lookups that returned an in-memory snapshot for SVC-08.",
			},
			[]string{"tier"},
		))
		c.cacheMisses = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "decision_rule_cache_misses_total",
				Help: "Total rule-cache misses for SVC-08, partitioned by tier.",
			},
			[]string{"tier"},
		))
		c.loadErrors = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "decision_rule_cache_load_errors_total",
				Help: "Total errors encountered while loading rules for SVC-08.",
			},
			[]string{"source"},
		))
		c.rulesLoaded = registerGaugeVec(reg, prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "decision_rule_cache_rules_loaded",
				Help: "Number of active rules loaded into the cache for an org (SVC-08).",
			},
			[]string{"org_id"},
		))
	}

	return c
}

// Get returns the active rule snapshot for orgID.
func (c *Cache) Get(ctx context.Context, orgID int64) ([]CachedRule, error) {
	c.markKnown(orgID)

	if e := c.fromMemory(orgID); e != nil {
		c.observeHit("memory")
		return e.rules, nil
	}
	c.observeMiss("memory")

	if rules, ok := c.fromValkey(ctx, orgID); ok {
		c.observeHit("valkey")
		c.storeMemory(orgID, rules)
		return rules, nil
	}
	c.observeMiss("valkey")

	rules, err := c.fromPostgres(ctx, orgID)
	if err != nil {
		c.observeLoadError("postgres")
		return nil, err
	}
	c.storeMemory(orgID, rules)
	c.storeValkey(ctx, orgID, rules)
	return rules, nil
}

// Refresh reloads every org we've served. Call from a background ticker.
func (c *Cache) Refresh(ctx context.Context) {
	c.mu.RLock()
	orgs := make([]int64, 0, len(c.knownOrgs))
	for id := range c.knownOrgs {
		orgs = append(orgs, id)
	}
	c.mu.RUnlock()

	for _, orgID := range orgs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rules, err := c.fromPostgres(ctx, orgID)
		if err != nil {
			c.observeLoadError("postgres_refresh")
			c.log.Warn().Err(err).Int64("org_id", orgID).Msg("decision rule cache refresh failed")
			continue
		}
		c.storeMemory(orgID, rules)
		c.storeValkey(ctx, orgID, rules)
	}
}

// StartRefreshLoop runs the periodic refresh until ctx is cancelled.
func (c *Cache) StartRefreshLoop(ctx context.Context) {
	if c == nil {
		return
	}
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Refresh(ctx)
		}
	}
}

func (c *Cache) fromMemory(orgID int64) *cacheEntry {
	c.mu.RLock()
	v, ok := c.entries[orgID]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	e, _ := v.Load().(*cacheEntry)
	if e == nil {
		return nil
	}
	if time.Since(e.loadedAt) > c.ttl {
		return nil
	}
	return e
}

func (c *Cache) storeMemory(orgID int64, rules []CachedRule) {
	c.mu.Lock()
	v, ok := c.entries[orgID]
	if !ok {
		v = &atomic.Value{}
		c.entries[orgID] = v
	}
	c.mu.Unlock()
	v.Store(&cacheEntry{rules: rules, loadedAt: time.Now()})
	if c.rulesLoaded != nil {
		c.rulesLoaded.WithLabelValues(fmt.Sprintf("%d", orgID)).Set(float64(len(rules)))
	}
}

func (c *Cache) fromValkey(ctx context.Context, orgID int64) ([]CachedRule, bool) {
	if c.valkey == nil {
		return nil, false
	}
	key := valkeyKey(orgID)
	cmd := c.valkey.Do(ctx, c.valkey.B().Get().Key(key).Build())
	if err := cmd.Error(); err != nil {
		if !valkeygo.IsValkeyNil(err) {
			c.log.Debug().Err(err).Str("key", key).Msg("decision rules cache valkey get failed")
		}
		return nil, false
	}
	body, err := cmd.AsBytes()
	if err != nil || len(body) == 0 {
		return nil, false
	}
	var rules []CachedRule
	if err := json.Unmarshal(body, &rules); err != nil {
		c.observeLoadError("valkey_decode")
		return nil, false
	}
	return rules, true
}

func (c *Cache) storeValkey(ctx context.Context, orgID int64, rules []CachedRule) {
	if c.valkey == nil {
		return
	}
	body, err := json.Marshal(rules)
	if err != nil {
		c.observeLoadError("valkey_encode")
		return
	}
	key := valkeyKey(orgID)
	if err := c.valkey.Do(ctx,
		c.valkey.B().Set().Key(key).Value(string(body)).Ex(c.ttl).Build(),
	).Error(); err != nil {
		c.observeLoadError("valkey_set")
		c.log.Debug().Err(err).Str("key", key).Msg("decision rules cache valkey set failed")
	}
}

func (c *Cache) fromPostgres(ctx context.Context, orgID int64) ([]CachedRule, error) {
	if c.queries == nil {
		return nil, errors.New("decision rule cache: no postgres queries configured")
	}
	rows, err := c.queries.ListActiveRulesForTargets(ctx, dbsqlc.ListActiveRulesForTargetsParams{
		Targets: c.targets,
		OrgID:   pgtype.Int8{Int64: orgID, Valid: orgID > 0},
	})
	if err != nil {
		return nil, fmt.Errorf("list active rules: %w", err)
	}

	out := make([]CachedRule, 0, len(rows))
	for _, r := range rows {
		var orgPtr *int64
		if r.OrgID.Valid {
			v := r.OrgID.Int64
			orgPtr = &v
		}
		out = append(out, CachedRule{
			ID:          r.ID,
			OrgID:       orgPtr,
			Name:        r.Name,
			Version:     r.Version,
			Target:      r.Target,
			ScoreImpact: int(r.ScoreImpact),
			Logic:       r.Logic,
		})
	}
	return out, nil
}

func (c *Cache) markKnown(orgID int64) {
	c.mu.Lock()
	c.knownOrgs[orgID] = struct{}{}
	c.mu.Unlock()
}

func valkeyKey(orgID int64) string {
	// Distinct from svc-04's header rules snapshot even when both services
	// validate against different rule Target sets stored in Postgres.
	return fmt.Sprintf("rules_cache:decision:{%d}", orgID)
}

func (c *Cache) observeHit(tier string) {
	if c == nil || c.cacheHits == nil {
		return
	}
	c.cacheHits.WithLabelValues(tier).Inc()
}

func (c *Cache) observeMiss(tier string) {
	if c == nil || c.cacheMisses == nil {
		return
	}
	c.cacheMisses.WithLabelValues(tier).Inc()
}

func (c *Cache) observeLoadError(source string) {
	if c == nil || c.loadErrors == nil {
		return
	}
	c.loadErrors.WithLabelValues(source).Inc()
}

func registerCounterVec(reg *prometheus.Registry, c *prometheus.CounterVec) *prometheus.CounterVec {
	if reg == nil {
		return c
	}
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
	}
	return c
}

func registerGaugeVec(reg *prometheus.Registry, g *prometheus.GaugeVec) *prometheus.GaugeVec {
	if reg == nil {
		return g
	}
	if err := reg.Register(g); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.GaugeVec); ok {
				return existing
			}
		}
	}
	return g
}
