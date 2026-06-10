// Package notifier implements the SVC-09 notification gate and dispatch.
//
// SVC-09 is a terminal consumer of emails.verdict (ARCH-SPEC §1-step6a). For
// every verdict it (1) reads the owning org's notification config from
// Postgres, (2) decides whether the verdict crosses the org's alert gate
// (risk_score >= notification_threshold OR verdict_label in {phishing,
// malware}), (3) applies a per-(org, campaign) Redis rate limit (notif key,
// 1h TTL, max one alert) and, when allowed, (4) dispatches the alert over the
// channels the org has enabled (email + webhook). Slack/Teams are out of scope
// for P2.
//
// Both transports default to Enabled=false in config, so every send is gated
// on its own config flag; SVC-09 never hard-requires SMTP or webhook
// credentials at startup, and an org may run email-only, webhook-only, or with
// no channel configured at all.
package notifier

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the SVC-09 Prometheus collectors. Names are prefixed
// notification_ to match the per-service metric namespace convention used by
// the other pipeline services.
type Metrics struct {
	// MessagesTotal counts consumed emails.verdict messages by outcome:
	//   gated     — crossed the alert gate and was dispatched (or attempted)
	//   below     — did not cross the gate (no alert)
	//   ratelimit — crossed the gate but suppressed by the rate limiter
	//   skip      — malformed / missing org config; offset committed
	//   error     — a transient failure that NACKs for redelivery
	MessagesTotal *prometheus.CounterVec // labels: outcome

	// AlertsTotal counts per-channel send attempts by result (sent|error).
	AlertsTotal *prometheus.CounterVec // labels: channel, result
}

// NewMetrics registers the SVC-09 collectors on reg and returns the holder. A
// nil reg yields unregistered collectors (tests).
func NewMetrics(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_messages_total",
			Help: "emails.verdict messages processed by SVC-09 partitioned by outcome.",
		},
		[]string{"outcome"},
	))

	m.AlertsTotal = registerCounterVec(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_alerts_total",
			Help: "Per-channel alert dispatch attempts partitioned by channel and result.",
		},
		[]string{"channel", "result"},
	))

	return m
}

func (m *Metrics) bumpOutcome(outcome string) {
	if m == nil || m.MessagesTotal == nil {
		return
	}
	m.MessagesTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) bumpAlert(channel, result string) {
	if m == nil || m.AlertsTotal == nil {
		return
	}
	m.AlertsTotal.WithLabelValues(channel, result).Inc()
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
