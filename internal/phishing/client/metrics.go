package client

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus collectors for the phishing client. All fields
// are nil-safe (callers may pass a zero-valued *Metrics to disable reporting)
// so test code and main binaries can opt in independently.
type Metrics struct {
	ScoresTotal    *prometheus.CounterVec // labels: verdict (phishing|benign|error), cache (hit|miss)
	ScoreDuration  prometheus.Histogram   // wall-clock seconds for one sidecar score (cache miss only)
	SidecarErrors  *prometheus.CounterVec // labels: stage (http|decode|status)
	CacheItemCount prometheus.Gauge       // current LRU entry count (set on each Get/Set)
}

// NewMetrics registers a fresh Metrics holder on reg. Pass a nil registry to
// get a no-op holder useful in tests where prometheus_default registration
// would conflict across packages.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		ScoresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "phishing_scores_total",
				Help: "Total phishing-detector scores, partitioned by verdict and cache outcome.",
			},
			[]string{"verdict", "cache"},
		),
		ScoreDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name: "phishing_score_duration_seconds",
				Help: "Wall-clock latency of a single sidecar /score call (cache misses only).",
				// Sidecar enrichment dominates; bucket around the expected SLO range
				// (typical cold call 0.5-5s, slow tail up to the 45s wrapping ctx).
				Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 45},
			},
		),
		SidecarErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "phishing_sidecar_errors_total",
				Help: "Phishing sidecar call errors, partitioned by stage.",
			},
			[]string{"stage"},
		),
		CacheItemCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "phishing_cache_items",
				Help: "Current number of entries in the phishing client's LRU cache.",
			},
		),
	}
	if reg == nil {
		return m
	}
	m.ScoresTotal = registerOrExisting(reg, m.ScoresTotal).(*prometheus.CounterVec)
	m.ScoreDuration = registerOrExistingHist(reg, m.ScoreDuration)
	m.SidecarErrors = registerOrExisting(reg, m.SidecarErrors).(*prometheus.CounterVec)
	m.CacheItemCount = registerOrExistingGauge(reg, m.CacheItemCount)
	return m
}

func registerOrExisting(reg prometheus.Registerer, c prometheus.Collector) prometheus.Collector {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			return already.ExistingCollector
		}
	}
	return c
}

func registerOrExistingHist(reg prometheus.Registerer, h prometheus.Histogram) prometheus.Histogram {
	if err := reg.Register(h); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(prometheus.Histogram); ok {
				return existing
			}
		}
	}
	return h
}

func registerOrExistingGauge(reg prometheus.Registerer, g prometheus.Gauge) prometheus.Gauge {
	if err := reg.Register(g); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
		}
	}
	return g
}

// IncScore is a nil-safe convenience. Callers in other packages (detector)
// bump the verdict counter through this.
func (m *Metrics) IncScore(verdict, cacheState string) {
	if m == nil || m.ScoresTotal == nil {
		return
	}
	m.ScoresTotal.WithLabelValues(verdict, cacheState).Inc()
}

// observeDuration is a nil-safe convenience used only inside this package.
func (m *Metrics) observeDuration(seconds float64) {
	if m == nil || m.ScoreDuration == nil {
		return
	}
	m.ScoreDuration.Observe(seconds)
}

// incSidecarError is a nil-safe convenience used only inside this package.
func (m *Metrics) incSidecarError(stage string) {
	if m == nil || m.SidecarErrors == nil {
		return
	}
	m.SidecarErrors.WithLabelValues(stage).Inc()
}

// setCacheItems is a nil-safe convenience used only inside this package.
func (m *Metrics) setCacheItems(n int) {
	if m == nil || m.CacheItemCount == nil {
		return
	}
	m.CacheItemCount.Set(float64(n))
}
