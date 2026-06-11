package processor

import (
	"github.com/prometheus/client_golang/prometheus"

	obsmetrics "github.com/saif/cybersiren/shared/observability/metrics"
)

// Metrics holds the Prometheus collectors specific to SVC-05 (the shared/kafka
// package owns the consumer/producer-level counters).
type Metrics struct {
	MessagesTotal *prometheus.CounterVec // result=ok|error
	ScoreTotal    *prometheus.CounterVec // bucket=low|medium|high|critical
	Duration      prometheus.Histogram
	ErrorsTotal   *prometheus.CounterVec // stage=consume|hash_lookup|vt|db_write|writeback_miss|publish
	VTLookups     *prometheus.CounterVec // outcome=hit|miss|cached|skipped|error
	HeuristicHits *prometheus.CounterVec // heuristic=entropy|ext_mismatch|dangerous_ext|macro|double_ext
}

// NewMetrics registers all SVC-05 metrics and returns the holder.
func NewMetrics(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attachment_analysis_messages_total",
			Help: "Total analysis.attachments messages processed by SVC-05 partitioned by result.",
		},
		[]string{"result"},
	))

	m.ScoreTotal = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attachment_analysis_score_total",
			Help: "Total per-email scores produced by SVC-05 partitioned by bucket.",
		},
		[]string{"bucket"},
	))

	m.Duration = obsmetrics.Register(reg, prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "attachment_analysis_duration_seconds",
			Help: "Per-message processing duration for SVC-05.",
			// A VT round-trip dominates when it misses cache; keep buckets up to
			// a few seconds.
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		},
	))

	m.ErrorsTotal = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attachment_analysis_errors_total",
			Help: "Total SVC-05 errors partitioned by pipeline stage.",
		},
		[]string{"stage"},
	))

	m.VTLookups = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attachment_analysis_vt_lookups_total",
			Help: "VirusTotal lookup outcomes partitioned by result.",
		},
		[]string{"outcome"},
	))

	m.HeuristicHits = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attachment_analysis_heuristic_hits_total",
			Help: "Heuristic fires recorded by SVC-05 partitioned by heuristic.",
		},
		[]string{"heuristic"},
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

func (m *Metrics) incVT(outcome string) {
	if m == nil || m.VTLookups == nil {
		return
	}
	m.VTLookups.WithLabelValues(outcome).Inc()
}

func (m *Metrics) incError(stage string) {
	if m == nil || m.ErrorsTotal == nil {
		return
	}
	m.ErrorsTotal.WithLabelValues(stage).Inc()
}

func (m *Metrics) incHeuristic(name string) {
	if m == nil || m.HeuristicHits == nil {
		return
	}
	m.HeuristicHits.WithLabelValues(name).Inc()
}
