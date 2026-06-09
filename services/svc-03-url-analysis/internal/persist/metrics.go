package persist

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus collectors for SVC-03's enrichment persistence.
// All methods are nil-safe so a nil *Metrics is a no-op (tests pass nil).
type Metrics struct {
	// Writes counts per-table write outcomes.
	// table=url|ti_match|job ; outcome=ok|error|skipped
	Writes *prometheus.CounterVec
	// PriorLookups counts prior-email enrichment-reuse reads.
	// result=hit|miss|error
	PriorLookups *prometheus.CounterVec
}

// NewMetrics registers a fresh Metrics holder on reg. reg may be nil for a
// no-op holder (the collectors are still allocated so methods stay nil-safe).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Writes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_enrichment_persist_writes_total",
				Help: "SVC-03 enrichment persistence writes partitioned by table and outcome.",
			},
			[]string{"table", "outcome"},
		),
		PriorLookups: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_enrichment_prior_lookups_total",
				Help: "SVC-03 prior-email enriched_threats lookups partitioned by result.",
			},
			[]string{"result"},
		),
	}
	if reg == nil {
		return m
	}
	m.Writes = registerOrReuseCounter(reg, m.Writes)
	m.PriorLookups = registerOrReuseCounter(reg, m.PriorLookups)
	return m
}

// IncWrite bumps the persist-writes counter for one table+outcome.
func (m *Metrics) IncWrite(table, outcome string) {
	if m == nil || m.Writes == nil {
		return
	}
	m.Writes.WithLabelValues(table, outcome).Inc()
}

// IncPrior bumps the prior-lookups counter for one result.
func (m *Metrics) IncPrior(result string) {
	if m == nil || m.PriorLookups == nil {
		return
	}
	m.PriorLookups.WithLabelValues(result).Inc()
}

func registerOrReuseCounter(reg prometheus.Registerer, c *prometheus.CounterVec) *prometheus.CounterVec {
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
