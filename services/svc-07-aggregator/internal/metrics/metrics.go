// Package metrics holds the Prometheus collectors specific to SVC-07.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics is the bag of SVC-07 Prometheus collectors. All names match
// docs/design/svc-07-08-design-brief.md §2.9.
type Metrics struct {
	MessagesTotal       *prometheus.CounterVec // labels: topic, status (ok|wait|error|complete|partial)
	CompletionLatencyMS prometheus.Histogram
	PartialCompletions  prometheus.Counter
	ActiveBuckets       prometheus.Gauge
	PublishErrors       *prometheus.CounterVec // labels: kind=publish|del|hsetnx|hset
}

// New registers the metrics on reg and returns the holder. Re-registering
// an already-registered collector returns the existing one — convenient
// for restart-tolerant test harnesses.
func New(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aggregator_messages_total",
			Help: "Total messages processed by SVC-07 partitioned by topic and status.",
		},
		[]string{"topic", "status"},
	))

	m.CompletionLatencyMS = registerHistogram(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aggregator_completion_latency_ms",
			Help:    "Time (ms) from first message to emails.scored emit.",
			Buckets: []float64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000},
		},
	))

	m.PartialCompletions = registerCounter(reg, prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "aggregator_partial_completions_total",
			Help: "Times the 30 s timeout fired and a partial emails.scored was emitted.",
		},
	))

	m.ActiveBuckets = registerGauge(reg, prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "aggregator_active_buckets",
			Help: "Approximate count of in-flight aggregator:{email_id} keys (sampled by sweeper).",
		},
	))

	m.PublishErrors = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aggregator_publish_errors_total",
			Help: "Errors during emails.scored publish or Valkey housekeeping, by kind.",
		},
		[]string{"kind"},
	))

	return m
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

func registerCounter(reg *prometheus.Registry, c prometheus.Counter) prometheus.Counter {
	if reg == nil {
		return c
	}
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
	}
	return c
}

func registerGauge(reg *prometheus.Registry, g prometheus.Gauge) prometheus.Gauge {
	if reg == nil {
		return g
	}
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

func registerHistogram(reg *prometheus.Registry, h prometheus.Histogram) prometheus.Histogram {
	if reg == nil {
		return h
	}
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
