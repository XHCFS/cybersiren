// STUB: replace with real implementation. Consumes emails.verdict and logs a
// "would-notify" line. NO real notifications, webhooks, or email sends.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-09-notification"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ConsumerTopics: []string{contracts.TopicEmailsVerdict},
		GroupID:        contracts.GroupNotification,
		Handler:        handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, _ svckit.Deps) error {
	var v contracts.EmailsVerdict
	if err := json.Unmarshal(msg.Value, &v); err != nil {
		return fmt.Errorf("decode verdict: %w", err)
	}

	zerolog.Ctx(ctx).Info().
		Str("email_id", v.Meta.EmailID).
		Str("verdict", v.VerdictLabel).
		Float64("risk_score", v.RiskScore).
		Msg("would-notify")
	return nil
}
