package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/observability/tracing"
)

// Notifier is the SVC-09 message handler. It owns the read-only org seam, the
// rate limiter, the (already config-gated) channel set, metrics and tracing.
// Construct it once in OnReady and call Handle per consumed message.
type Notifier struct {
	orgs     OrgReader
	limiter  RateLimiter
	channels map[string]Channel
	metrics  *Metrics
	log      zerolog.Logger
	tracer   trace.Tracer
}

// New builds a Notifier. channels is the config-gated transport set from
// BuildChannels (it may be empty — an org with no configured transport is a
// valid no-op deployment). limiter may be nil, in which case rate limiting is
// skipped and every gated verdict is allowed (fail-open: a missing limiter
// must never silently drop alerts).
func New(orgs OrgReader, limiter RateLimiter, channels map[string]Channel, m *Metrics, log zerolog.Logger) *Notifier {
	return &Notifier{
		orgs:     orgs,
		limiter:  limiter,
		channels: channels,
		metrics:  m,
		log:      log,
		tracer:   tracing.Tracer("svc-09-notification"),
	}
}

// Handle processes one emails.verdict message. The error contract follows the
// rest of the pipeline: return nil to commit the offset (terminal outcomes —
// malformed input, below-gate, rate-limited, dispatched), return non-nil to
// NACK for redelivery (transient failures — org-load DB errors). Channel send
// failures are best-effort and do NOT NACK: the rate-limit token has already
// been claimed for the window, so a redelivery would be suppressed anyway.
func (n *Notifier) Handle(ctx context.Context, msg kafkaconsumer.Message) error {
	ctx, span := n.tracer.Start(ctx, "notification.process", trace.WithAttributes(
		attribute.Int("messaging.kafka.partition", msg.Partition),
		attribute.Int64("messaging.kafka.offset", msg.Offset),
	))
	defer span.End()

	var v contracts.EmailsVerdict
	if err := json.Unmarshal(msg.Value, &v); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "decode failed")
		n.metrics.bumpOutcome("skip")
		n.log.Error().Err(err).
			Int("partition", msg.Partition).Int64("offset", msg.Offset).
			Msg("malformed emails.verdict; skipping (offset will commit)")
		return nil
	}

	log := n.log.With().
		Int64("email_id", v.Meta.EmailID).
		Int64("org_id", v.Meta.OrgID).
		Str("verdict", v.VerdictLabel).
		Int("risk_score", v.RiskScore).
		Logger()

	span.SetAttributes(
		attribute.Int64("email_id", v.Meta.EmailID),
		attribute.Int64("org_id", v.Meta.OrgID),
		attribute.String("verdict_label", v.VerdictLabel),
		attribute.Int("risk_score", v.RiskScore),
	)

	// Resolve the org's notification preferences (threshold, channels, admins).
	prefs, err := n.orgs.Load(ctx, v.Meta.OrgID)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			// Nobody to notify and a replay will never find the row.
			span.SetStatus(codes.Ok, "org not found; skipping")
			n.metrics.bumpOutcome("skip")
			log.Warn().Msg("org not found for verdict; skipping notification")
			return nil
		}
		// Transient DB failure — NACK so the verdict is retried.
		span.RecordError(err)
		span.SetStatus(codes.Error, "org load failed")
		n.metrics.bumpOutcome("error")
		log.Error().Err(err).Msg("failed to load org notification config; will retry")
		return fmt.Errorf("load org prefs: %w", err)
	}

	// Threshold / label gate.
	if !Gate(v, prefs.Threshold) {
		span.SetAttributes(attribute.Bool("notification.gated", false))
		n.metrics.bumpOutcome("below")
		log.Debug().Int("threshold", prefs.Threshold).Msg("verdict below alert gate; no notification")
		return nil
	}
	span.SetAttributes(
		attribute.Bool("notification.gated", true),
		attribute.Int("notification.threshold", prefs.Threshold),
	)

	// Per-(org, campaign) rate limit. Fail-open on limiter errors so a Redis
	// blip never drops a real alert.
	if n.limiter != nil {
		key := RateLimitKey(v.Meta.OrgID, v.CampaignID, v.Meta.EmailID)
		allowed, rlErr := n.limiter.Allow(ctx, key)
		switch {
		case rlErr != nil:
			// Degrade to allow; a missing/failed limiter must not suppress alerts.
			log.Warn().Err(rlErr).Str("key", key).Msg("rate limiter error; allowing alert (fail-open)")
		case !allowed:
			span.SetAttributes(attribute.Bool("notification.rate_limited", true))
			n.metrics.bumpOutcome("ratelimit")
			log.Info().Str("key", key).Msg("alert suppressed by per-campaign rate limit")
			return nil
		}
	}

	n.dispatch(ctx, v, prefs, log)
	n.metrics.bumpOutcome("gated")
	span.SetStatus(codes.Ok, "alert dispatched")
	return nil
}

// dispatch sends the alert over every channel the org has BOTH enabled (in its
// notification_channels) AND configured (present in the config-gated channel
// set). A channel listed by the org but not configured in this deployment is
// skipped; a channel configured but not enabled by the org is skipped. Sends
// are best-effort — failures are logged and counted, never propagated.
func (n *Notifier) dispatch(ctx context.Context, v contracts.EmailsVerdict, prefs OrgPrefs, log zerolog.Logger) {
	alert := AlertFrom(v, prefs)
	sent := 0
	for name, ch := range n.channels {
		if !prefs.HasChannel(name) {
			continue
		}
		if err := ch.Send(ctx, alert); err != nil {
			n.metrics.bumpAlert(name, "error")
			log.Error().Err(err).Str("channel", name).Msg("alert dispatch failed")
			continue
		}
		n.metrics.bumpAlert(name, "sent")
		sent++
		log.Info().Str("channel", name).Msg("alert dispatched")
	}
	if sent == 0 {
		// Gated + rate-limit-passed but no channel actually fired: either the
		// org enabled only channels this deployment hasn't configured, or every
		// send failed. Surface it so a misconfiguration is visible.
		log.Warn().Msg("verdict crossed alert gate but no channel delivered the alert")
	}
}
