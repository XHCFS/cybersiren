// Package main is the entrypoint for SVC-07 Score Aggregator.
//
// SVC-07 is a stateless synchronisation barrier: it consumes
// analysis.plans + the four scores.* topics, gathers per-email state in
// Valkey, and emits exactly one emails.scored message per email_id once
// all expected component scores have arrived (or 30 s have elapsed
// since the first message, whichever comes first).
//
// Per-email state lives entirely in Valkey under the key
// `aggregator:{email_id}` (TTL 120 s). Multiple instances may run in
// parallel; coordination uses an HSETNX-based __publishing lock to
// prevent duplicate emits.
//
// See docs/design/svc-07-08-design-brief.md §2 for the full contract.
package main

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/saif/cybersiren/services/svc-07-aggregator/internal/aggregator"
	"github.com/saif/cybersiren/services/svc-07-aggregator/internal/metrics"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-07-aggregator"

func main() {
	var (
		agg     *aggregator.Aggregator
		sweeper *aggregator.Sweeper
	)

	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsValkey:    true,
		ProducerTopics: []string{contracts.TopicEmailsScored},
		ConsumerTopics: []string{
			contracts.TopicAnalysisPlans,
			contracts.TopicScoresURL,
			contracts.TopicScoresHeader,
			contracts.TopicScoresAttachment,
			contracts.TopicScoresNLP,
		},
		GroupID: contracts.GroupAggregator,
		OnReady: func(ctx context.Context, deps svckit.Deps) error {
			m := metrics.New(deps.Registry)
			store := aggregator.NewValkeyStore(deps.Valkey)

			producer, ok := deps.Producers[contracts.TopicEmailsScored]
			if !ok {
				return errProducerMissing
			}

			agg = aggregator.New(aggregator.Config{}, store, producer, m, deps.Log)
			sweeper = aggregator.NewSweeper(agg)

			// Start the sweeper in its own goroutine. Its lifetime is
			// bound to ctx (the same shared context svckit cancels on
			// SIGINT/SIGTERM) so it exits cleanly on shutdown.
			g, gctx := errgroup.WithContext(ctx)
			g.Go(func() error { return sweeper.Run(gctx) })

			// We deliberately do not Wait on g here — svckit owns the
			// shutdown lifecycle. The goroutine returns nil when ctx
			// is cancelled.
			go func() {
				_ = g.Wait()
			}()

			return nil
		},
		Handler: func(ctx context.Context, msg kafkaconsumer.Message, _ svckit.Deps) error {
			if agg == nil {
				return errNotReady
			}
			return agg.Handle(ctx, msg)
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// errors as package-level vars so `go vet` and the linter don't complain
// about err.New inline at the wiring site.
var (
	errProducerMissing = errAggregatorMain("svc-07: producer for emails.scored not configured")
	errNotReady        = errAggregatorMain("svc-07: aggregator not initialised; OnReady must run first")
)

type errAggregatorMain string

func (e errAggregatorMain) Error() string { return string(e) }
