package main

import (
	"context"
	"encoding/json"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/kafka/consumer"
)

// startConsumers launches background consumers for emails.scored and
// emails.verdict that feed the in-memory store. They are best-effort: a Kafka
// outage only means the breakdown panel stays empty — the upload/forward path
// still works. The handler never NACKs (a malformed demo record must not stall
// the partition).
func startConsumers(ctx context.Context, cfg config, st *store, log zerolog.Logger) {
	reg := prometheus.NewRegistry()

	run := func(topic, group string, apply func([]byte)) {
		c, err := consumer.New(consumer.Config{
			Brokers:  cfg.KafkaBrokers,
			Topic:    topic,
			GroupID:  group,
			ClientID: "demo-dashboard",
		}, log, reg)
		if err != nil {
			log.Error().Err(err).Str("topic", topic).Msg("consumer init failed; breakdown unavailable")
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.Run(ctx, func(_ context.Context, m consumer.Message) error {
				apply(m.Value)
				return nil
			})
		}()
	}

	run(contracts.TopicEmailsScored, "demo-dashboard-scored", func(b []byte) {
		var es contracts.EmailsScored
		if err := json.Unmarshal(b, &es); err == nil && es.Meta.EmailID != "" {
			st.applyScored(&es)
		}
	})
	run(contracts.TopicEmailsVerdict, "demo-dashboard-verdict", func(b []byte) {
		var ev contracts.EmailsVerdict
		if err := json.Unmarshal(b, &ev); err == nil && ev.Meta.EmailID != "" {
			st.applyVerdict(&ev)
		}
	})
}
