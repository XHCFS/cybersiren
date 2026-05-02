// Package consumer is the CyberSiren-side wrapper over kgo's consuming API.
// One GroupConsumer fetches from a set of topics under a fixed consumer
// group, runs a handler per record (with W3C trace context extracted from
// Kafka headers via kotel), and commits offsets only after success.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kotel"
	"go.opentelemetry.io/otel"

	sharedkafka "github.com/saif/cybersiren/shared/kafka"
)

// Handler processes one Kafka record. Returning an error logs it and skips
// commit for that batch (record will be redelivered after group rebalance).
type Handler func(ctx context.Context, rec *kgo.Record) error

// Config wires up the consumer.
type Config struct {
	Brokers       []string
	ClientID      string
	GroupID       string
	Topics        []string
	Service       string // service name used as a Prometheus label
}

// GroupConsumer owns the kgo.Client and a goroutine that pumps records into
// the handler. Use Run to start the loop; it returns when ctx is cancelled.
type GroupConsumer struct {
	client  *kgo.Client
	tracer  *kotel.Tracer
	cfg     Config
	log     zerolog.Logger
}

// New connects a kgo.Client configured for group consumption.
func New(cfg Config, reg *prometheus.Registry, log zerolog.Logger) (*GroupConsumer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("kafka consumer: no brokers configured")
	}
	if cfg.GroupID == "" {
		return nil, fmt.Errorf("kafka consumer: group_id is required")
	}
	if len(cfg.Topics) == 0 {
		return nil, fmt.Errorf("kafka consumer: at least one topic required")
	}

	sharedkafka.RegisterMetrics(reg)

	tracer := kotel.NewTracer(
		kotel.TracerProvider(otel.GetTracerProvider()),
		kotel.TracerPropagator(otel.GetTextMapPropagator()),
		kotel.ClientID(cfg.ClientID),
		kotel.ConsumerGroup(cfg.GroupID),
	)
	k := kotel.NewKotel(kotel.WithTracer(tracer))

	cli, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		kgo.ConsumerGroup(cfg.GroupID),
		kgo.ConsumeTopics(cfg.Topics...),
		kgo.DisableAutoCommit(),
		kgo.WithHooks(k.Hooks()...),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka consumer: %w", err)
	}

	return &GroupConsumer{
		client: cli,
		tracer: tracer,
		cfg:    cfg,
		log:    log.With().Str("component", "kafka-consumer").Str("group", cfg.GroupID).Logger(),
	}, nil
}

// Run blocks polling the broker until ctx is cancelled. Each record runs
// Handler under a child OTel span (kotel re-extracts traceparent from the
// record's Kafka headers).
func (g *GroupConsumer) Run(ctx context.Context, h Handler) error {
	g.log.Info().Strs("topics", g.cfg.Topics).Msg("kafka consumer started")
	defer g.log.Info().Msg("kafka consumer stopped")

	for {
		fetches := g.client.PollFetches(ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			// Surface non-context errors; ctx-canceled is a normal shutdown.
			for _, e := range errs {
				if errors.Is(e.Err, context.Canceled) || errors.Is(e.Err, context.DeadlineExceeded) {
					return nil
				}
				g.log.Error().Err(e.Err).Str("topic", e.Topic).Msg("fetch error")
			}
		}
		if fetches.Empty() {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		batchOK := true
		fetches.EachRecord(func(rec *kgo.Record) {
			recCtx, span := g.tracer.WithProcessSpan(rec)
			start := time.Now()

			recLog := g.log.With().
				Str("topic", rec.Topic).
				Int32("partition", rec.Partition).
				Int64("offset", rec.Offset).
				Str("email_id", string(rec.Key)).
				Logger()
			recCtx = recLog.WithContext(recCtx)

			if err := h(recCtx, rec); err != nil {
				recLog.Error().Err(err).Msg("kafka handler error")
				batchOK = false
				span.RecordError(err)
				span.End()
				return
			}

			sharedkafka.IncConsumed(g.cfg.Service, rec.Topic)
			sharedkafka.ObserveProcessing(g.cfg.Service, rec.Topic, time.Since(start).Seconds())
			span.End()
		})

		if batchOK {
			if err := g.client.CommitUncommittedOffsets(ctx); err != nil {
				g.log.Error().Err(err).Msg("commit offsets failed")
			}
		}
	}
}

// Close shuts down the kgo.Client.
func (g *GroupConsumer) Close() {
	g.client.Close()
}

// Ping issues a metadata request to verify broker reachability.
func (g *GroupConsumer) Ping(ctx context.Context) error {
	return g.client.Ping(ctx)
}
