// svc-09-notification consumes emails.verdict and dispatches rate-limited
// alerts to each org's enabled channels (ARCH-SPEC Step 6a). Webhook/Slack are
// stubbed as structured log lines; the email channel resolves admin recipients.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-09-notification/internal/notifier"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-09-notification"

var alerter *notifier.Notifier

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ConsumerTopics: []string{contracts.TopicEmailsVerdict},
		GroupID:        contracts.GroupNotification,
		OnReady: func(_ context.Context, deps svckit.Deps) error {
			alerter = notifier.NewFromPool(deps.Pool, deps.Valkey, deps.Log)
			deps.Log.Info().Msg("notifier ready")
			return nil
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var v contracts.EmailsVerdict
	if err := json.Unmarshal(msg.Value, &v); err != nil {
		deps.Log.Error().Err(err).
			Int("partition", msg.Partition).Int64("offset", msg.Offset).
			Msg("malformed emails.verdict; skipping (offset will commit)")
		return nil
	}
	if err := alerter.Process(ctx, v); err != nil {
		return fmt.Errorf("notify email_id=%d: %w", v.Meta.EmailID, err)
	}
	return nil
}
