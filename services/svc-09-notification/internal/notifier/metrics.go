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
	"github.com/prometheus/client_golang/prometheus"

	obsmetrics "github.com/saif/cybersiren/shared/observability/metrics"
)

// Outcome label values for MessagesTotal. A gated verdict ends in exactly one
// of OutcomeGated / OutcomeGatedUndelivered depending on whether any channel
// actually delivered the alert, so a zero-transport misconfig is a metric, not
// just a log line.
const (
	OutcomeGated            = "gated"             // crossed the gate AND ≥1 channel delivered
	OutcomeGatedUndelivered = "gated_undelivered" // crossed the gate but no channel delivered
	OutcomeBelow            = "below"             // did not cross the gate (no alert)
	OutcomeRateLimit        = "ratelimit"         // crossed the gate but suppressed by the limiter
	OutcomeSkip             = "skip"              // malformed / missing org config; offset committed
	OutcomeError            = "error"             // a transient failure that NACKs for redelivery
)

// Alert result label values for AlertsTotal.
const (
	AlertSent         = "sent"          // channel delivered the alert
	AlertError        = "error"         // channel send failed
	AlertNoRecipients = "no_recipients" // channel had nothing to address (email, no admins)
)

// Metrics holds the SVC-09 Prometheus collectors. Names are prefixed
// notification_ to match the per-service metric namespace convention used by
// the other pipeline services.
type Metrics struct {
	// MessagesTotal counts consumed emails.verdict messages by outcome. See the
	// Outcome* constants for the label set.
	MessagesTotal *prometheus.CounterVec // labels: outcome

	// AlertsTotal counts per-channel send attempts by result. See the Alert*
	// constants (sent|error|no_recipients).
	AlertsTotal *prometheus.CounterVec // labels: channel, result

	// RateLimitFailOpenTotal counts gated verdicts that were allowed through
	// because the rate limiter ERRORED (e.g. a Redis outage), distinct from a
	// normal within-limit allow. A non-zero rate here means rate limiting is
	// silently disabled and duplicate alerts may be going out.
	RateLimitFailOpenTotal prometheus.Counter
}

// NewMetrics registers the SVC-09 collectors on reg and returns the holder. A
// nil reg yields unregistered collectors (tests).
func NewMetrics(reg *prometheus.Registry) *Metrics {
	m := &Metrics{}

	m.MessagesTotal = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_messages_total",
			Help: "emails.verdict messages processed by SVC-09 partitioned by outcome.",
		},
		[]string{"outcome"},
	))

	m.AlertsTotal = obsmetrics.Register(reg, prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_alerts_total",
			Help: "Per-channel alert dispatch attempts partitioned by channel and result (sent|error|no_recipients).",
		},
		[]string{"channel", "result"},
	))

	m.RateLimitFailOpenTotal = obsmetrics.Register(reg, prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "notification_ratelimit_failopen_total",
			Help: "Gated verdicts allowed because the rate limiter errored (rate limiting silently disabled).",
		},
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

func (m *Metrics) bumpRateLimitFailOpen() {
	if m == nil || m.RateLimitFailOpenTotal == nil {
		return
	}
	m.RateLimitFailOpenTotal.Inc()
}
