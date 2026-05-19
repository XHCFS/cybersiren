package url

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// ScanMetrics holds the Prometheus collectors that describe URL-scan outcomes
// across both the HTTP handler (cmd/url-analysis) and the Kafka worker
// (cmd/url-pipeline). All instance methods are nil-safe so callers can pass a
// nil holder in tests.
type ScanMetrics struct {
	ScansTotal    *prometheus.CounterVec // outcome=guard_allowlisted|guard_typosquat|guard_brand|ti_phishing|ml_phishing|ml_benign|fallback
	ScanDuration  prometheus.Histogram   // wall-clock end-to-end /scan
	StageErrors   *prometheus.CounterVec // stage=normalize|guard|l1|ti|l2
	GuardChecks   *prometheus.CounterVec // hit=allowlisted|typosquat|brand_in_subdomain|none
	L2Invocations *prometheus.CounterVec // reason=ti_miss|ti_low_confidence
}

// NewScanMetrics registers a fresh ScanMetrics holder on reg. reg may be nil
// for a no-op holder.
func NewScanMetrics(reg prometheus.Registerer) *ScanMetrics {
	m := &ScanMetrics{
		ScansTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_scans_total",
				Help: "Total /scan invocations partitioned by the outcome that drove the verdict.",
			},
			[]string{"outcome"},
		),
		ScanDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name: "url_scan_duration_seconds",
				Help: "End-to-end /scan wall-clock latency (HTTP handler).",
				// Guard short-circuits land sub-millisecond; full pipeline with L2
				// enrichment can run multi-second on cold URLs.
				Buckets: []float64{0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 1, 2, 5, 10},
			},
		),
		StageErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_scan_stage_errors_total",
				Help: "Errors encountered in the /scan pipeline, partitioned by stage.",
			},
			[]string{"stage"},
		),
		GuardChecks: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_guard_checks_total",
				Help: "Domain guard outcomes partitioned by hit type.",
			},
			[]string{"hit"},
		),
		L2Invocations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "url_l2_invocations_total",
				Help: "L2 fusion sidecar invocations from svc-03 partitioned by why TI did not short-circuit.",
			},
			[]string{"reason"},
		),
	}
	if reg == nil {
		return m
	}
	m.ScansTotal = registerOrReuseCounter(reg, m.ScansTotal)
	m.ScanDuration = registerOrReuseHistogram(reg, m.ScanDuration)
	m.StageErrors = registerOrReuseCounter(reg, m.StageErrors)
	m.GuardChecks = registerOrReuseCounter(reg, m.GuardChecks)
	m.L2Invocations = registerOrReuseCounter(reg, m.L2Invocations)
	return m
}

// IncOutcome bumps the scans_total counter for an outcome label.
func (m *ScanMetrics) IncOutcome(outcome string) {
	if m == nil || m.ScansTotal == nil {
		return
	}
	m.ScansTotal.WithLabelValues(outcome).Inc()
}

// IncGuard bumps the guard_checks_total counter.
func (m *ScanMetrics) IncGuard(hit string) {
	if m == nil || m.GuardChecks == nil {
		return
	}
	m.GuardChecks.WithLabelValues(hit).Inc()
}

// IncL2 bumps the l2_invocations_total counter.
func (m *ScanMetrics) IncL2(reason string) {
	if m == nil || m.L2Invocations == nil {
		return
	}
	m.L2Invocations.WithLabelValues(reason).Inc()
}

// IncStageError bumps the stage_errors_total counter.
func (m *ScanMetrics) IncStageError(stage string) {
	if m == nil || m.StageErrors == nil {
		return
	}
	m.StageErrors.WithLabelValues(stage).Inc()
}

// ObserveDuration records an end-to-end /scan duration in seconds.
func (m *ScanMetrics) ObserveDuration(seconds float64) {
	if m == nil || m.ScanDuration == nil {
		return
	}
	m.ScanDuration.Observe(seconds)
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

func registerOrReuseHistogram(reg prometheus.Registerer, h prometheus.Histogram) prometheus.Histogram {
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
