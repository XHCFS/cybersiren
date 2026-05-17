// Package producer is a thin synchronous Kafka writer wrapper used by
// services that publish to a single topic per writer.
//
// Internally this uses github.com/twmb/franz-go (with the kotel plugin for
// W3C trace-context propagation through Kafka headers), but the exported
// API matches the historical kafka-go-based wrapper so callers can swap
// the broker library without code churn.
package producer

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

	sharedkafka "github.com/saif/cybersiren/shared/kafka"
)

// Config holds the parameters needed to create a Producer.
type Config struct {
	// Brokers is a comma- or whitespace-separated list of host:port pairs.
	Brokers string
	// Topic is the single Kafka topic this producer writes to.
	Topic string
	// ClientID identifies this instance to the broker.
	ClientID string
	// BatchTimeout caps how long records are buffered before a send.
	BatchTimeout time.Duration
	// WriteTimeout caps a single ProduceSync call.
	WriteTimeout time.Duration
	// Retries is how many *additional* attempts to make after the first
	// ProduceSync try (retries=0 → 1 attempt; retries=3 → 4 attempts).
	Retries int
}

// Producer publishes JSON-serialised messages to a fixed Kafka topic.
type Producer struct {
	client *kgo.Client
	topic  string
	log    zerolog.Logger

	publishedTotal *prometheus.CounterVec
	errorsTotal    *prometheus.CounterVec
	publishLatency *prometheus.HistogramVec

	writeTimeout time.Duration
}

// New constructs a Producer.
func New(cfg Config, log zerolog.Logger, reg *prometheus.Registry) (*Producer, error) {
	if strings.TrimSpace(cfg.Brokers) == "" {
		return nil, errors.New("kafka producer: brokers is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("kafka producer: topic is required")
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}

	sharedkafka.RegisterMetrics(reg)

	tracer := kotel.NewTracer(
		kotel.TracerProvider(otel.GetTracerProvider()),
		kotel.TracerPropagator(otel.GetTextMapPropagator()),
		kotel.ClientID(cfg.ClientID),
	)
	k := kotel.NewKotel(kotel.WithTracer(tracer))

	cli, err := kgo.NewClient(
		kgo.SeedBrokers(splitBrokers(cfg.Brokers)...),
		kgo.ClientID(cfg.ClientID),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.ProducerBatchCompression(kgo.ZstdCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.WithHooks(k.Hooks()...),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	p := &Producer{
		client:       cli,
		topic:        cfg.Topic,
		log:          log.With().Str("component", "kafka-producer").Str("topic", cfg.Topic).Logger(),
		writeTimeout: cfg.WriteTimeout,
	}

	p.publishedTotal = registerCounterVec(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_producer",
		Name:      "published_total",
		Help:      "Records produced, labelled by topic and result.",
	}, []string{"topic", "result"}))

	p.errorsTotal = registerCounterVec(reg, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_producer",
		Name:      "errors_total",
		Help:      "Producer errors, labelled by topic.",
	}, []string{"topic"}))

	p.publishLatency = registerHistogramVec(reg, prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cybersiren",
		Subsystem: "kafka_producer",
		Name:      "publish_seconds",
		Help:      "Wall-clock time per publish, labelled by topic.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"topic"}))

	return p, nil
}

// Publish sends one record. The active OTel span on ctx is propagated into
// Kafka headers via kotel. retries is the count of *extra* tries after the
// first attempt (retries=3 → up to 4 ProduceSync calls).
func (p *Producer) Publish(ctx context.Context, key, value []byte, retries int) error {
	if p == nil || p.client == nil {
		return errors.New("kafka producer: not initialised")
	}

	start := time.Now()
	var lastErr error

	attempts := normalizePublishAttempts(retries)

	for attempt := 0; attempt < attempts; attempt++ {
		ctxAttempt, cancel := context.WithTimeout(ctx, p.writeTimeout)
		rec := &kgo.Record{Topic: p.topic, Key: key, Value: value}
		err := p.client.ProduceSync(ctxAttempt, rec).FirstErr()
		cancel()

		if err == nil {
			p.observePublishCount(p.topic, "ok")
			p.observePublishLatency(p.topic, time.Since(start))
			sharedkafka.IncProduced(p.topic, p.topic)
			return nil
		}

		lastErr = err
		p.log.Warn().Err(err).Int("attempt", attempt+1).Int("of", attempts).Msg("publish attempt failed")

		if attempt+1 < attempts {
			time.Sleep(backoffDuration(attempt))
		}
	}

	p.observePublishCount(p.topic, "error")
	p.observeError(p.topic)
	return fmt.Errorf("kafka publish to %s failed after %d attempts: %w", p.topic, attempts, lastErr)
}

// Close flushes pending records and shuts down the underlying client.
func (p *Producer) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.client.Flush(flushCtx); err != nil {
		p.log.Warn().Err(err).Msg("flush on close")
	}
	p.client.Close()
	return nil
}

// Ping verifies broker reachability. Used by /healthz.
func (p *Producer) Ping(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("kafka producer ping: %w", err)
	}
	return nil
}

// normalizePublishAttempts maps the retries parameter to a total attempt count.
func normalizePublishAttempts(retries int) int {
	a := retries + 1
	if a < 1 {
		return 1
	}
	return a
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

func backoffDuration(attempt int) time.Duration {
	d := time.Duration(1<<attempt) * 100 * time.Millisecond
	if d > 5*time.Second {
		return 5 * time.Second
	}
	return d
}

func (p *Producer) observePublishCount(topic, result string) {
	if p.publishedTotal != nil {
		p.publishedTotal.WithLabelValues(topic, result).Inc()
	}
}

func (p *Producer) observeError(topic string) {
	if p.errorsTotal != nil {
		p.errorsTotal.WithLabelValues(topic).Inc()
	}
}

func (p *Producer) observePublishLatency(topic string, d time.Duration) {
	if p.publishLatency != nil {
		p.publishLatency.WithLabelValues(topic).Observe(d.Seconds())
	}
}

func registerCounterVec(reg *prometheus.Registry, c *prometheus.CounterVec) *prometheus.CounterVec {
	if reg == nil {
		return c
	}
	if err := reg.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
	}
	return c
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
