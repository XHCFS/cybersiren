// Package metrics owns SVC-08 Prometheus collectors. Names match
// docs/design/svc-07-08-design-brief.md §3.12.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	MessagesTotal      *prometheus.CounterVec // labels: status (ok|error)
	RiskScore          prometheus.Histogram
	VerdictTotal       *prometheus.CounterVec // labels: label
	CampaignTotal      *prometheus.CounterVec // labels: type (new|existing)
	DBWriteDuration    prometheus.Histogram
	RulesFiredTotal    *prometheus.CounterVec // labels: rule_id
	ProcessingDuration prometheus.Histogram
}

// New registers all SVC-08 metrics on reg and returns the holder.
func New(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "decision_messages_total",
			Help: "emails.scored messages processed by SVC-08 partitioned by status.",
		},
		[]string{"status"},
	))

	m.RiskScore = registerHistogram(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "decision_risk_score",
			Help:    "Distribution of final risk_score values produced by SVC-08.",
			Buckets: []float64{0, 25, 50, 75, 100},
		},
	))

	m.VerdictTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "decision_verdict_total",
			Help: "Verdicts emitted by SVC-08 partitioned by label.",
		},
		[]string{"label"},
	))

	m.CampaignTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "decision_campaign_total",
			Help: "Campaign UPSERT outcomes by type (new|existing).",
		},
		[]string{"type"},
	))

	m.DBWriteDuration = registerHistogram(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "decision_db_write_duration_seconds",
			Help:    "Single-transaction decision DB write duration.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	))

	m.RulesFiredTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "decision_rules_fired_total",
			Help: "Per-rule fire counts in the decision engine.",
		},
		[]string{"rule_id"},
	))

	m.ProcessingDuration = registerHistogram(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "decision_processing_duration_seconds",
			Help:    "End-to-end SVC-08 per-message processing duration.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5},
		},
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
