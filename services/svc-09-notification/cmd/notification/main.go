// Command notification is the SVC-09 Notification Service binary. It consumes
// emails.verdict from svc-08-decision, applies the per-org alert gate
// (risk_score >= organisations.notification_threshold OR verdict_label in
// {phishing, malware}), rate-limits to one alert per (org, campaign) per hour
// via Redis, and dispatches alerts over the channels the org has enabled —
// SMTP email + webhook only (Slack/Teams are out of scope for P2).
//
// Both transports default to disabled in config; SVC-09 never hard-requires
// SMTP or webhook credentials at startup. Bootstrap (config, logger, Kafka,
// Postgres pool, Valkey, Prometheus, OpenTelemetry, graceful shutdown) is
// handled by shared/svckit; this file wires the notifier to that scaffolding.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-09-notification/internal/notifier"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-09-notification"

var (
	errNotReady = errors.New("svc-09: notifier not yet initialised")
	errNoPool   = errors.New("svc-09: postgres pool unavailable")
)

func main() {
	var n *notifier.Notifier

	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ConsumerTopics: []string{contracts.TopicEmailsVerdict},
		GroupID:        contracts.GroupNotification,
		OnReady: func(_ context.Context, deps svckit.Deps) error {
			if deps.Pool == nil {
				return errNoPool
			}

			// Validate only the channels the deployment has enabled. Disabled
			// channels (the default for both) are not validated, so SVC-09 boots
			// fine with no transport configured — it simply won't deliver.
			if err := deps.Cfg.Notification.Validate(); err != nil {
				return fmt.Errorf("validate notification config: %w", err)
			}

			channels := notifier.BuildChannels(deps.Cfg.Notification)

			var limiter notifier.RateLimiter
			if deps.Valkey != nil {
				limiter = notifier.NewValkeyRateLimiter(deps.Valkey)
			}

			n = notifier.New(
				notifier.NewPGOrgReader(deps.Pool, deps.Log),
				limiter,
				channels,
				notifier.NewMetrics(deps.Registry),
				deps.Log,
			)

			enabled := make([]string, 0, len(channels))
			for name := range channels {
				enabled = append(enabled, name)
			}
			deps.Log.Info().
				Strs("channels_enabled", enabled).
				Bool("rate_limit", limiter != nil).
				Msg("notification service ready")
			return nil
		},
		Handler: func(ctx context.Context, msg kafkaconsumer.Message, _ svckit.Deps) error {
			if n == nil {
				return errNotReady
			}
			return n.Handle(ctx, msg)
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
