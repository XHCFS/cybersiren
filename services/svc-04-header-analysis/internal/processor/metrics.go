package processor

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus collectors specific to SVC-04 (the
// shared/kafka package owns the consumer/producer-level counters).
type Metrics struct {
	MessagesTotal   *prometheus.CounterVec // result=ok|error
	ScoreTotal      *prometheus.CounterVec // bucket=low|medium|high|critical
	Duration        prometheus.Histogram
	ErrorsTotal     *prometheus.CounterVec // stage=consume|rules_load|rule_eval|ti_lookup|db_write|publish
	RulesFiredTotal *prometheus.CounterVec // rule_id (label cardinality bounded by rule set size)
	WriteRetries    *prometheus.CounterVec // outcome=ok|exhausted
}

// NewMetrics registers all SVC-04 metrics and returns the holder.
func NewMetrics(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "header_analysis_messages_total",
			Help: "Total analysis.headers messages processed by SVC-04 partitioned by result.",
		},
		[]string{"result"},
	))

	m.ScoreTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "header_analysis_score_total",
			Help: "Total scores produced by SVC-04 partitioned by bucket.",
		},
		[]string{"bucket"},
	))

	m.Duration = registerHistogram(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "header_analysis_duration_seconds",
			Help:    "Per-message processing duration for SVC-04.",
			// Go-only header analysis should typically complete in <100ms.
			// Keep bucket granularity tight around the expected SLO range.
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		},
	))

	m.ErrorsTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "header_analysis_errors_total",
			Help: "Total SVC-04 errors partitioned by pipeline stage.",
		},
		[]string{"stage"},
	))

	m.RulesFiredTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "header_analysis_rules_fired_total",
			Help: "Total rule fires recorded by SVC-04 partitioned by rule_id.",
		},
		[]string{"rule_id"},
	))

	m.WriteRetries = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "header_analysis_db_write_retries_total",
			Help: "rule_hits transaction retry outcomes.",
		},
		[]string{"outcome"},
	))

	return m
}

// ScoreBucket maps a 0-100 score to a coarse bucket label.
func ScoreBucket(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
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
