// Command decision is the SVC-08 Decision Engine binary. It consumes
// emails.scored from svc-07-aggregator, computes the final risk score,
// applies the rule engine, manages campaigns, persists everything in
// one Postgres transaction, and emits emails.verdict.
//
// All bootstrap (config, logger, Kafka clients, Postgres pool, Valkey
// client, Prometheus, OpenTelemetry, graceful shutdown) is handled by
// shared/svckit. This file's job is to wire the engine to that
// scaffolding and start the rules-cache refresh loop.
package main

import (
	"context"
	"errors"
	"os"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/engine"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/metrics"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/persist"
	rulespkg "github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName         = "svc-08-decision"
	defaultDBRetries    = 3
	defaultPubRetries   = 3
	defaultModelVersion = "decision-v1"
)

var (
	errNotReady          = errors.New("svc-08: engine not yet initialised")
	errProducerMissing   = errors.New("svc-08: producer for emails.verdict missing")
	errInvalidPipelineDB = errors.New("svc-08: postgres pool unavailable")
)

func main() {
	var eng *engine.Engine

	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ProducerTopics: []string{contracts.TopicEmailsVerdict},
		ConsumerTopics: []string{contracts.TopicEmailsScored},
		GroupID:        contracts.GroupDecisionEngine,
		OnReady: func(ctx context.Context, deps svckit.Deps) error {
			if deps.Pool == nil {
				return errInvalidPipelineDB
			}
			producer, ok := deps.Producers[contracts.TopicEmailsVerdict]
			if !ok {
				return errProducerMissing
			}

			m := metrics.New(deps.Registry)

			cache := rulespkg.NewCache(
				deps.Pool,
				deps.Valkey,
				rulespkg.CacheConfig{},
				deps.Log,
				deps.Registry,
			)
			go cache.StartRefreshLoop(ctx)

			simhash := campaign.NewComputer(deps.Valkey, campaign.SimHashThreshold, deps.Log, m.SimhashLookupIndex)
			writer := persist.NewWriter(deps.Pool, defaultDBRetries, deps.Log)

			eng = engine.New(
				engine.Config{
					BlendWeights:         engine.DefaultWeights(),
					Shrinkage:            campaign.DefaultShrinkage(),
					SimHashThreshold:     campaign.SimHashThreshold,
					PublishRetryAttempts: defaultPubRetries,
					DefaultModelVersion:  defaultModelVersion,
				},
				cache,
				simhash,
				writer,
				producer,
				m,
				deps.Log,
			)

			deps.Log.Info().
				Str("model_version", defaultModelVersion).
				Int("simhash_threshold", campaign.SimHashThreshold).
				Msg("decision engine ready")
			return nil
		},
		Handler: func(ctx context.Context, msg kafkaconsumer.Message, _ svckit.Deps) error {
			if eng == nil {
				return errNotReady
			}
			return eng.Handle(ctx, msg)
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
