// Package producer is a thin synchronous Kafka writer wrapper used by
// services that publish to a single topic per writer.
//
// SCOPE: identical philosophy to shared/kafka/consumer — keep the surface
// area small until a second consumer of this package shows up.
package producer

import (
	"context"
	"errors"
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

// Config holds the parameters needed to create a Producer.
type Config struct {
	Brokers      string
	Topic        string
	ClientID     string
	BatchTimeout time.Duration
	WriteTimeout time.Duration
	// Retries caps the number of attempts WriteMessages will make per
	// publish (in addition to kafka-go's internal retries). When 0, a
	// single best-effort attempt is made.
	Retries int
}

// Producer publishes JSON-serialised messages to a fixed Kafka topic.
type Producer struct {
	writer *kafkago.Writer
	log    zerolog.Logger
	tracer trace.Tracer

	publishedTotal *prometheus.CounterVec
	errorsTotal    *prometheus.CounterVec
	publishLatency *prometheus.HistogramVec
}

// New constructs a Producer.
func New(cfg Config, log zerolog.Logger, reg *prometheus.Registry) (*Producer, error) {
	if strings.TrimSpace(cfg.Brokers) == "" {
		return nil, errors.New("kafka producer: brokers is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("kafka producer: topic is required")
	}

	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 50 * time.Millisecond
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}

	writer := &kafkago.Writer{
		Addr:                   kafkago.TCP(splitBrokers(cfg.Brokers)...),
		Topic:                  cfg.Topic,
		Balancer:               &kafkago.Hash{},
		BatchTimeout:           cfg.BatchTimeout,
		WriteTimeout:           cfg.WriteTimeout,
		AllowAutoTopicCreation: false,
		RequiredAcks:           kafkago.RequireAll,
		Async:                  false,
	}

	p := &Producer{
		writer: writer,
		log:    log,
		tracer: tracing.Tracer("shared/kafka/producer"),
	}

	if reg != nil {
		p.publishedTotal = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kafka_producer_messages_total",
				Help: "Total Kafka messages published, partitioned by result (ok|error).",
			},
			[]string{"topic", "result"},
		))
		p.errorsTotal = registerCounterVec(reg, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kafka_producer_errors_total",
				Help: "Total Kafka producer errors.",
			},
			[]string{"topic"},
		))
		p.publishLatency = registerHistogramVec(reg, prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kafka_producer_publish_duration_seconds",
				Help:    "Time spent publishing a single Kafka message.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"topic"},
		))
	}

	return p, nil
}

// Publish writes a single message to Kafka. Trace context from ctx is
// injected as Kafka headers so downstream consumers can resume the span.
//
// retries controls the exponential-backoff retry budget IN ADDITION to
// any retry handling kafka-go performs internally. retries=0 = single
// attempt. The caller's ctx cancellation always wins.
func (p *Producer) Publish(ctx context.Context, key, value []byte, retries int) error {
	if p == nil || p.writer == nil {
		return errors.New("kafka producer: not initialised")
	}

	topic := p.writer.Topic

	ctx, span := p.tracer.Start(
		ctx,
		"kafka.publish",
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination", topic),
		),
	)
	defer span.End()

	headers := injectTraceContext(ctx)

	var lastErr error
	startedAt := time.Now()

	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}

		err := p.writer.WriteMessages(ctx, kafkago.Message{
			Key:     key,
			Value:   value,
			Headers: headers,
		})
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err

		// Don't burn the rest of the budget if the context died.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			break
		}

		backoff := backoffDuration(attempt)
		p.log.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_attempts", attempts).
			Dur("backoff", backoff).
			Str("topic", topic).
			Msg("kafka publish failed, retrying")

		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
			attempt = attempts // exit loop
		case <-time.After(backoff):
		}
	}

	p.observePublishLatency(topic, time.Since(startedAt))

	if lastErr != nil {
		p.observePublishCount(topic, "error")
		p.observeError(topic)
		span.RecordError(lastErr)
		span.SetStatus(codes.Error, lastErr.Error())
		return lastErr
	}

	p.observePublishCount(topic, "ok")
	span.SetStatus(codes.Ok, "")
	return nil
}

// Close flushes pending messages and closes the underlying writer.
func (p *Producer) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}

func injectTraceContext(ctx context.Context) []kafkago.Header {
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if len(carrier) == 0 {
		return nil
	}
	headers := make([]kafkago.Header, 0, len(carrier))
	for k, v := range carrier {
		headers = append(headers, kafkago.Header{Key: k, Value: []byte(v)})
	}
	return headers
}

func backoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := 100 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > 5*time.Second {
			d = 5 * time.Second
			break
		}
	}
	return d
}

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

func (p *Producer) observePublishCount(topic, result string) {
	if p == nil || p.publishedTotal == nil {
		return
	}
	p.publishedTotal.WithLabelValues(topic, result).Inc()
}

func (p *Producer) observeError(topic string) {
	if p == nil || p.errorsTotal == nil {
		return
	}
	p.errorsTotal.WithLabelValues(topic).Inc()
}

func (p *Producer) observePublishLatency(topic string, d time.Duration) {
	if p == nil || p.publishLatency == nil {
		return
	}
	p.publishLatency.WithLabelValues(topic).Observe(d.Seconds())
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
