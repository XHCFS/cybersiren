package analyzer

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the SVC-05 Prometheus collectors. All methods are nil-safe so a
// nil holder can be passed in tests.
type Metrics struct {
	Scores         *prometheus.CounterVec // outcome=malicious|heuristic|clean
	HeuristicFires *prometheus.CounterVec // rule=high_entropy|ext_mime_mismatch|dangerous_ext|macro_office|double_ext
	PersistErrors  prometheus.Counter
}

// NewMetrics registers a fresh Metrics holder on reg (nil reg → no-op holder).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Scores: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attachment_scores_total",
			Help: "Attachment scoring outcomes partitioned by what drove the score.",
		}, []string{"outcome"}),
		HeuristicFires: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attachment_heuristic_fires_total",
			Help: "Individual attachment heuristic rule fires.",
		}, []string{"rule"}),
		PersistErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "attachment_persist_errors_total",
			Help: "Best-effort email_attachments.risk_score write failures (do not block scores.attachment).",
		}),
	}
	if reg == nil {
		return m
	}
	m.Scores = reuseCounterVec(reg, m.Scores)
	m.HeuristicFires = reuseCounterVec(reg, m.HeuristicFires)
	m.PersistErrors = reuseCounter(reg, m.PersistErrors)
	return m
}

// IncScore bumps the scores_total counter (outcome=malicious|heuristic|clean).
func (m *Metrics) IncScore(outcome string) {
	if m == nil || m.Scores == nil {
		return
	}
	m.Scores.WithLabelValues(outcome).Inc()
}

// IncHeuristic bumps the heuristic_fires_total counter for a rule label.
func (m *Metrics) IncHeuristic(rule string) {
	if m == nil || m.HeuristicFires == nil {
		return
	}
	m.HeuristicFires.WithLabelValues(rule).Inc()
}

// IncPersistError bumps the persist_errors_total counter.
func (m *Metrics) IncPersistError() {
	if m == nil || m.PersistErrors == nil {
		return
	}
	m.PersistErrors.Inc()
}

func reuseCounterVec(reg prometheus.Registerer, c *prometheus.CounterVec) *prometheus.CounterVec {
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

func reuseCounter(reg prometheus.Registerer, c prometheus.Counter) prometheus.Counter {
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
