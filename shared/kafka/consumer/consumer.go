// Package consumer is a single-topic at-least-once Kafka consumer wrapper.
//
// Internally this uses github.com/twmb/franz-go (with the kotel plugin for
// W3C trace-context propagation through Kafka headers); the exported API
// matches the historical kafka-go-based wrapper so callers swap broker
// libraries without code churn.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kotel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	sharedkafka "github.com/saif/cybersiren/shared/kafka"
)

// Config holds the parameters needed to create a Consumer.
type Config struct {
	// Brokers is a comma- or whitespace-separated list of host:port pairs.
	Brokers string
	// Topic is the single Kafka topic this consumer subscribes to.
	Topic string
	// GroupID is the Kafka consumer group ID. Two consumers with the
	// same GroupID share partitions of Topic between them.
	GroupID string
	// ClientID identifies this instance to the broker.
	ClientID string
	// PollTimeout caps how long PollFetches blocks per loop iteration.
	// Defaults to 250ms; smaller values shorten shutdown latency.
	PollTimeout time.Duration
}

// Handler processes a single Kafka message and returns nil on success.
//
// On non-nil error the consumer logs the failure, increments error metrics,
// and skips committing the offset for that record (the message will be
// re-read on consumer restart or partition rebalance).
type Handler func(ctx context.Context, msg Message) error

// Message is the consumer's view of a Kafka record. The embedded
// SpanContext carries any W3C trace context that the producer propagated.
type Message struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   []Header
	Time      time.Time

	SpanContext trace.SpanContext
}

// Header is a single Kafka message header.
type Header struct {
	Key   string
	Value []byte
}

// Consumer is a single-topic at-least-once Kafka consumer.
type Consumer struct {
	client      *kgo.Client
	tracer      *kotel.Tracer
	cfg         Config
	pollTimeout time.Duration
	log         zerolog.Logger

	messagesTotal     *prometheus.CounterVec
	errorsTotal       *prometheus.CounterVec
	processingLatency *prometheus.HistogramVec
}

// New constructs a Consumer.
func New(cfg Config, log zerolog.Logger, reg *prometheus.Registry) (*Consumer, error) {
	if strings.TrimSpace(cfg.Brokers) == "" {
		return nil, errors.New("kafka consumer: brokers is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("kafka consumer: topic is required")
	}
	if strings.TrimSpace(cfg.GroupID) == "" {
		return nil, errors.New("kafka consumer: group_id is required")
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = 250 * time.Millisecond
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
		kgo.SeedBrokers(splitBrokers(cfg.Brokers)...),
		kgo.ClientID(cfg.ClientID),
		kgo.ConsumerGroup(cfg.GroupID),
		kgo.ConsumeTopics(cfg.Topic),
		kgo.DisableAutoCommit(),
		kgo.WithHooks(k.Hooks()...),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka consumer: %w", err)
	}

	c := &Consumer{
		client:      cli,
		tracer:      tracer,
		cfg:         cfg,
		pollTimeout: cfg.PollTimeout,
		log:         log.With().Str("component", "kafka-consumer").Str("group", cfg.GroupID).Str("topic", cfg.Topic).Logger(),
	}

	c.messagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_consumer",
		Name:      "messages_total",
		Help:      "Records consumed, labelled by topic, group, and result.",
	}, []string{"topic", "group", "result"}))

	c.errorsTotal = registerCounterVec(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_consumer",
		Name:      "errors_total",
		Help:      "Consumer errors, labelled by topic, group, and stage.",
	}, []string{"topic", "group", "stage"}))

	c.processingLatency = registerHistogramVec(reg, prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_consumer",
		Name:      "process_seconds",
		Help:      "Wall-clock time per consumed record.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"topic", "group"}))

	return c, nil
}

// Run blocks polling the broker until ctx is cancelled. Each record is
// passed through Handler under a child OTel span (kotel re-extracts
// traceparent from Kafka headers).
func (c *Consumer) Run(ctx context.Context, handler Handler) error {
	if c == nil {
		return errors.New("kafka consumer: nil receiver")
	}
	if handler == nil {
		return errors.New("kafka consumer: handler is required")
	}

	c.log.Info().Msg("kafka consumer started")
	defer c.log.Info().Msg("kafka consumer stopped")

	for {
		if ctx.Err() != nil {
			return nil
		}
		pollCtx, cancel := context.WithTimeout(ctx, c.pollTimeout)
		fetches := c.client.PollFetches(pollCtx)
		cancel()

		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				if errors.Is(e.Err, context.Canceled) || errors.Is(e.Err, context.DeadlineExceeded) {
					continue
				}
				c.observeError(c.cfg.Topic, c.cfg.GroupID, "fetch")
				c.log.Error().Err(e.Err).Str("topic", e.Topic).Msg("fetch error")
			}
		}
		if fetches.Empty() {
			continue
		}

		batchOK := true
		fetches.EachRecord(func(rec *kgo.Record) {
			recCtx, span := c.tracer.WithProcessSpan(rec)
			start := time.Now()

			recLog := c.log.With().
				Str("topic", rec.Topic).
				Int32("partition", rec.Partition).
				Int64("offset", rec.Offset).
				Str("email_id", string(rec.Key)).
				Logger()
			recCtx = recLog.WithContext(recCtx)

			msg := Message{
				Topic:       rec.Topic,
				Partition:   int(rec.Partition),
				Offset:      rec.Offset,
				Key:         rec.Key,
				Value:       rec.Value,
				Headers:     toHeaders(rec.Headers),
				Time:        rec.Timestamp,
				SpanContext: trace.SpanFromContext(recCtx).SpanContext(),
			}

			if err := handler(recCtx, msg); err != nil {
				c.observeError(c.cfg.Topic, c.cfg.GroupID, "handler")
				c.observeMessages(c.cfg.Topic, c.cfg.GroupID, "error")
				recLog.Error().Err(err).Msg("kafka handler error; offset will not be committed")
				batchOK = false
				span.RecordError(err)
				span.End()
				return
			}

			sharedkafka.IncConsumed(c.cfg.GroupID, rec.Topic)
			c.observeMessages(c.cfg.Topic, c.cfg.GroupID, "ok")
			c.observeProcessingLatency(c.cfg.Topic, c.cfg.GroupID, time.Since(start))
			span.End()
		})

		if batchOK {
			commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := c.client.CommitUncommittedOffsets(commitCtx); err != nil {
				c.observeError(c.cfg.Topic, c.cfg.GroupID, "commit")
				c.log.Error().Err(err).Msg("commit offsets failed")
			}
			cancel()
		}
	}
}

// Close shuts down the kgo.Client.
func (c *Consumer) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	c.client.Close()
	return nil
}

// Ping verifies broker reachability.
func (c *Consumer) Ping(ctx context.Context) error {
	return c.client.Ping(ctx)
}

func toHeaders(in []kgo.RecordHeader) []Header {
	if len(in) == 0 {
		return nil
	}
	out := make([]Header, 0, len(in))
	for _, h := range in {
		out = append(out, Header{Key: h.Key, Value: h.Value})
	}
	return out
}

func splitBrokers(brokers string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(brokers, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		s := strings.TrimSpace(part)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c *Consumer) observeMessages(topic, group, result string) {
	if c.messagesTotal != nil {
		c.messagesTotal.WithLabelValues(topic, group, result).Inc()
	}
}

func (c *Consumer) observeError(topic, group, stage string) {
	if c.errorsTotal != nil {
		c.errorsTotal.WithLabelValues(topic, group, stage).Inc()
	}
}

func (c *Consumer) observeProcessingLatency(topic, group string, d time.Duration) {
	if c.processingLatency != nil {
		c.processingLatency.WithLabelValues(topic, group).Observe(d.Seconds())
	}
}

func registerCounterVec(reg *prometheus.Registry, cv *prometheus.CounterVec) *prometheus.CounterVec {
	if reg == nil {
		return cv
	}
	if err := reg.Register(cv); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
	}
	return cv
}

func registerHistogramVec(reg *prometheus.Registry, h *prometheus.HistogramVec) *prometheus.HistogramVec {
	if reg == nil {
		return h
	}
	if err := reg.Register(h); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
	}
	return h
}
