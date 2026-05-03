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
)

// CacheConfig configures Cache behaviour.
type CacheConfig struct {
	// Targets is the set of rules.target values SVC-04 cares about.
	// Defaults to {"header", "email"} when empty.
	Targets []string
	// TTL controls in-memory + Valkey cache expiry. ARCH-SPEC §5 mandates 60s.
	TTL time.Duration
}

// Cache is the rule cache with three tiers:
//
//  1. Hot in-memory snapshot per (org_id) — atomic.Value for lock-free reads.
//  2. Valkey "rules_cache:header:{org_id}" string for cross-instance warm-start.
//  3. Postgres "rules" table — source of truth, hit only when both caches miss.
//
// A single background goroutine refreshes every Org we've ever served at
// the configured TTL. There is no per-message DB hit on the happy path.
type Cache struct {
	pool    *pgxpool.Pool
	queries *dbsqlc.Queries
	valkey  valkeygo.Client
	log     zerolog.Logger
	ttl     time.Duration
	targets []string

	mu        sync.RWMutex
	entries   map[int64]*atomic.Value // org_id -> *cacheEntry
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

// NewCache constructs a Cache. valkey is optional (pass nil to disable
// the cross-instance warm cache and rely purely on in-memory + DB).
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
		cfg.Targets = []string{"header", "email"}
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
				Name: "header_rule_cache_hits_total",
				Help: "Total rule-cache lookups that returned an in-memory snapshot.",
			},
			[]string{"tier"},
		))
		c.cacheMisses = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "header_rule_cache_misses_total", Help: "Total rule-cache misses partitioned by tier."},
			[]string{"tier"},
		))
		c.loadErrors = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "header_rule_cache_load_errors_total", Help: "Total errors encountered while loading rules."},
			[]string{"source"},
		))
		c.rulesLoaded = registerGaugeVec(reg, prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "header_rule_cache_rules_loaded", Help: "Number of active rules loaded into the cache for an org."},
			[]string{"org_id"},
		))
	}

	return c
}

// Get returns the active rule snapshot for orgID. On the happy path it
// is purely in-memory. On miss it loads from Valkey, then from Postgres.
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

// Refresh reloads every org we've served. Intended to be called by a
// 60-second ticker from main.go.
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
			c.log.Warn().Err(err).Int64("org_id", orgID).Msg("rule cache refresh failed")
			continue
		}
		c.storeMemory(orgID, rules)
		c.storeValkey(ctx, orgID, rules)
	}
}

// StartRefreshLoop runs the periodic refresh until ctx is cancelled.
// Returns immediately if c is nil.
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
		// A simple cache miss is signalled by a nil reply, which valkey-go
		// returns as an error containing "Nil". Treat any error as a miss.
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
		c.log.Debug().Err(err).Str("key", key).Msg("rules cache valkey set failed")
	}
}

func (c *Cache) fromPostgres(ctx context.Context, orgID int64) ([]CachedRule, error) {
	if c.queries == nil {
		return nil, errors.New("rule cache: no postgres queries configured")
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
	return fmt.Sprintf("rules_cache:header:{%d}", orgID)
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
