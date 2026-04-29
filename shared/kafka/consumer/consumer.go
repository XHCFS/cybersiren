// Package consumer is a minimal at-least-once Kafka consumer wrapper
// built on top of github.com/segmentio/kafka-go.
//
// SCOPE: This is the first Kafka consumer in the CyberSiren codebase.
// It intentionally provides only what SVC-04 needs today:
//
//   - Manual commit semantics (offset only commits after successful processing).
//   - W3C trace-context propagation through Kafka headers ("traceparent").
//   - Prometheus counters for messages / errors / processing latency.
//   - Graceful shutdown via context cancellation.
//
// FOLLOW-UP: Once SVC-02 / SVC-05 / SVC-07 land, lift any new requirements
// (multi-topic subscriptions, consumer groups across multiple topics,
// dead-letter handling) into this package rather than fork it per-service.
package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	kafkago "github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/saif/cybersiren/shared/observability/tracing"
)

// Config holds the parameters needed to create a Consumer.
type Config struct {
	// Brokers is a comma- or space-separated list of host:port pairs.
	Brokers string
	// Topic is the single Kafka topic this consumer subscribes to.
	Topic string
	// GroupID is the Kafka consumer group ID. Two consumers with the
	// same GroupID will share partitions of Topic between them.
	GroupID string
	// MinBytes/MaxBytes tune fetch behaviour. Sensible defaults applied
	// in New() when zero.
	MinBytes int
	MaxBytes int
	// MaxWait caps the time the broker waits before returning a fetch
	// response that has fewer than MinBytes available. Default 1s.
	MaxWait time.Duration
	// CommitInterval = 0 enables synchronous commits via CommitMessages
	// (which is what we want for at-least-once delivery). Do not set.
}

// Handler processes a single Kafka message and returns nil on success.
// On non-nil error the offset is NOT committed and the message will be
// re-delivered on the next fetch (after the broker's session timeout).
type Handler func(ctx context.Context, msg Message) error

// Message is a thin wrapper over kafkago.Message that exposes only what
// callers need plus the OpenTelemetry context derived from the message
// headers (traceparent / tracestate).
type Message struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   []Header
	Time      time.Time

	// SpanContext carries any trace context propagated through Kafka
	// headers. Empty when the producer did not propagate context.
	SpanContext trace.SpanContext
}

// Header is a single Kafka message header.
type Header struct {
	Key   string
	Value []byte
}

// Consumer is a single-topic at-least-once Kafka consumer.
type Consumer struct {
	reader *kafkago.Reader
	log    zerolog.Logger
	tracer trace.Tracer

	messagesTotal     *prometheus.CounterVec
	errorsTotal       *prometheus.CounterVec
	processingLatency *prometheus.HistogramVec
}

// New builds a Consumer. If reg is non-nil, three metrics are registered:
//
//	kafka_consumer_messages_total{topic, group, result}
//	kafka_consumer_errors_total{topic, group, stage}
//	kafka_consumer_processing_duration_seconds{topic, group}
func New(cfg Config, log zerolog.Logger, reg *prometheus.Registry) (*Consumer, error) {
	if strings.TrimSpace(cfg.Brokers) == "" {
		return nil, errors.New("kafka consumer: brokers is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("kafka consumer: topic is required")
	}
	if strings.TrimSpace(cfg.GroupID) == "" {
		return nil, errors.New("kafka consumer: group id is required")
	}

	if cfg.MinBytes == 0 {
		cfg.MinBytes = 1
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 10 << 20 // 10 MiB
	}
	if cfg.MaxWait == 0 {
		cfg.MaxWait = time.Second
	}

	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:        splitBrokers(cfg.Brokers),
		Topic:          cfg.Topic,
		GroupID:        cfg.GroupID,
		MinBytes:       cfg.MinBytes,
		MaxBytes:       cfg.MaxBytes,
		MaxWait:        cfg.MaxWait,
		CommitInterval: 0, // explicit commits via CommitMessages
		StartOffset:    kafkago.LastOffset,
		Logger:         kafkaInfoLogger{log: log.With().Str("kafka", "consumer").Logger()},
		ErrorLogger:    kafkaErrorLogger{log: log.With().Str("kafka", "consumer").Logger()},
	})

	c := &Consumer{
		reader: reader,
		log:    log,
		tracer: tracing.Tracer("shared/kafka/consumer"),
	}

	if reg != nil {
		c.messagesTotal = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kafka_consumer_messages_total",
				Help: "Total Kafka messages handled by the consumer wrapper, partitioned by result (ok|error).",
			},
			[]string{"topic", "group", "result"},
		))
		c.errorsTotal = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kafka_consumer_errors_total",
				Help: "Total Kafka consumer errors partitioned by stage (fetch|handler|commit).",
			},
			[]string{"topic", "group", "stage"},
		))
		c.processingLatency = registerHistogramVec(reg, prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kafka_consumer_processing_duration_seconds",
				Help:    "Time spent inside the user-provided handler for each Kafka message.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"topic", "group"},
		))
	}

	return c, nil
}

// Run blocks the calling goroutine, fetching messages from Kafka and
// dispatching them to handler one at a time. The offset is only
// committed after handler returns nil. The loop exits when ctx is
// cancelled or the underlying reader returns a non-recoverable error.
//
// Errors returned by handler are logged but DO NOT terminate the loop —
// they only suppress the offset commit so the message will be redelivered.
func (c *Consumer) Run(ctx context.Context, handler Handler) error {
	if c == nil {
		return errors.New("kafka consumer: nil receiver")
	}
	if c.reader == nil {
		return errors.New("kafka consumer: reader not initialised")
	}
	if handler == nil {
		return errors.New("kafka consumer: handler is required")
	}

	topic := c.reader.Config().Topic
	group := c.reader.Config().GroupID

	for {
		// Honour cancellation before fetching to avoid one extra round-trip.
		if err := ctx.Err(); err != nil {
			return nil
		}

		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			c.observeError(topic, group, "fetch")
			c.log.Error().Err(err).Str("topic", topic).Str("group", group).Msg("kafka fetch failed")
			// Brief sleep so we don't spin on persistent broker errors.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}

		spanCtx := extractTraceContext(msg.Headers)
		msgCtx := trace.ContextWithRemoteSpanContext(ctx, spanCtx)
		msgCtx, span := c.tracer.Start(
			msgCtx,
			"kafka.consume",
			trace.WithSpanKind(trace.SpanKindConsumer),
			trace.WithAttributes(
				attribute.String("messaging.system", "kafka"),
				attribute.String("messaging.destination", topic),
				attribute.String("messaging.kafka.consumer_group", group),
				attribute.Int("messaging.kafka.partition", msg.Partition),
				attribute.Int64("messaging.kafka.offset", msg.Offset),
			),
		)

		startedAt := time.Now()
		handlerErr := handler(msgCtx, fromKafkaMessage(msg, spanCtx))
		duration := time.Since(startedAt)

		c.observeProcessingLatency(topic, group, duration)

		if handlerErr != nil {
			c.observeError(topic, group, "handler")
			c.observeMessages(topic, group, "error")
			span.RecordError(handlerErr)
			span.SetStatus(codes.Error, handlerErr.Error())
			span.End()
			c.log.Error().
				Err(handlerErr).
				Str("topic", topic).
				Int("partition", msg.Partition).
				Int64("offset", msg.Offset).
				Msg("kafka handler returned error; offset will not be committed")
			continue
		}

		// At-least-once: commit only after handler success.
		if commitErr := c.reader.CommitMessages(ctx, msg); commitErr != nil {
			if errors.Is(commitErr, context.Canceled) {
				span.End()
				return nil
			}
			c.observeError(topic, group, "commit")
			c.observeMessages(topic, group, "error")
			span.RecordError(commitErr)
			span.SetStatus(codes.Error, commitErr.Error())
			span.End()
			c.log.Error().Err(commitErr).Msg("kafka commit failed")
			continue
		}

		c.observeMessages(topic, group, "ok")
		span.SetStatus(codes.Ok, "")
		span.End()
	}
}

// Close shuts down the underlying reader. Safe to call once.
func (c *Consumer) Close() error {
	if c == nil || c.reader == nil {
		return nil
	}
	if err := c.reader.Close(); err != nil {
		return fmt.Errorf("kafka reader close: %w", err)
	}
	return nil
}

func fromKafkaMessage(msg kafkago.Message, sc trace.SpanContext) Message {
	headers := make([]Header, 0, len(msg.Headers))
	for _, h := range msg.Headers {
		headers = append(headers, Header{Key: h.Key, Value: h.Value})
	}
	return Message{
		Topic:       msg.Topic,
		Partition:   msg.Partition,
		Offset:      msg.Offset,
		Key:         msg.Key,
		Value:       msg.Value,
		Headers:     headers,
		Time:        msg.Time,
		SpanContext: sc,
	}
}

// extractTraceContext maps Kafka message headers (traceparent / tracestate)
// onto an OTel propagation carrier and returns the resulting SpanContext.
// Returns an empty SpanContext if headers are missing.
func extractTraceContext(headers []kafkago.Header) trace.SpanContext {
	if len(headers) == 0 {
		return trace.SpanContext{}
	}

	carrier := propagation.MapCarrier{}
	for _, h := range headers {
		carrier[h.Key] = string(h.Value)
	}

	ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
	return trace.SpanContextFromContext(ctx)
}

// splitBrokers normalises a Brokers string into a slice. The Brokers
// string can be comma- or space-separated.
func splitBrokers(brokers string) []string {
	out := make([]string, 0, 4)
	for _, part := range strings.FieldsFunc(brokers, func(r rune) bool {
		return r == ',' || r == ' '
	}) {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (c *Consumer) observeError(topic, group, stage string) {
	if c == nil || c.errorsTotal == nil {
		return
	}
	c.errorsTotal.WithLabelValues(topic, group, stage).Inc()
}

func (c *Consumer) observeMessages(topic, group, result string) {
	if c == nil || c.messagesTotal == nil {
		return
	}
	c.messagesTotal.WithLabelValues(topic, group, result).Inc()
}

func (c *Consumer) observeProcessingLatency(topic, group string, d time.Duration) {
	if c == nil || c.processingLatency == nil {
		return
	}
	c.processingLatency.WithLabelValues(topic, group).Observe(d.Seconds())
}

// kafkaInfoLogger / kafkaErrorLogger adapt zerolog to kafka-go's Logger interface.
type kafkaInfoLogger struct{ log zerolog.Logger }

func (l kafkaInfoLogger) Printf(format string, args ...interface{}) {
	l.log.Debug().Msgf(format, args...)
}

type kafkaErrorLogger struct{ log zerolog.Logger }

func (l kafkaErrorLogger) Printf(format string, args ...interface{}) {
	l.log.Error().Msgf(format, args...)
}

func registerCounterVec(reg *prometheus.Registry, c *prometheus.CounterVec) *prometheus.CounterVec {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
	}
	return c
}

func registerHistogramVec(reg *prometheus.Registry, h *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := reg.Register(h); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
	}
	return h
}

// Compile-time check: keep this in case kafka-go changes its Logger interface.
var (
	_ kafkago.Logger = kafkaInfoLogger{}
	_ kafkago.Logger = kafkaErrorLogger{}
)
