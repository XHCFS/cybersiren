// Package producer is the CyberSiren-side wrapper over kgo's producing API.
// It serialises payloads to JSON, injects W3C trace context as Kafka headers
// (via kotel hooks set up in shared/kafka), and emits Prometheus counters.
package producer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kotel"
	"go.opentelemetry.io/otel"

	sharedkafka "github.com/saif/cybersiren/shared/kafka"
)

// Producer is a thin wrapper over *kgo.Client tuned for the CyberSiren
// pipeline (idempotent acks, zstd compression, traceparent injected via
// kotel). Construct one per service.
type Producer struct {
	client  *kgo.Client
	service string
	log     zerolog.Logger
}

// Config wires up the producer.
type Config struct {
	Brokers  []string
	ClientID string
	Service  string // service name used as a Prometheus label
}

// New connects a kgo.Client and returns a Producer. The caller must Close()
// it on shutdown.
func New(cfg Config, reg *prometheus.Registry, log zerolog.Logger) (*Producer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("kafka producer: no brokers configured")
	}

	sharedkafka.RegisterMetrics(reg)

	tracer := kotel.NewTracer(
		kotel.TracerProvider(otel.GetTracerProvider()),
		kotel.TracerPropagator(otel.GetTextMapPropagator()),
		kotel.ClientID(cfg.ClientID),
	)
	k := kotel.NewKotel(kotel.WithTracer(tracer))

	cli, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		kgo.ProducerBatchCompression(kgo.ZstdCompression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.WithHooks(k.Hooks()...),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	return &Producer{
		client:  cli,
		service: cfg.Service,
		log:     log.With().Str("component", "kafka-producer").Logger(),
	}, nil
}

// Publish serialises payload to JSON and produces it to topic with the given
// partition key (use email_id). The call blocks until the broker acks. The
// active OTel span on ctx is propagated into Kafka headers via kotel.
func (p *Producer) Publish(ctx context.Context, topic, key string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload for %s: %w", topic, err)
	}

	rec := &kgo.Record{
		Topic: topic,
		Key:   []byte(key),
		Value: body,
	}

	if err := p.client.ProduceSync(ctx, rec).FirstErr(); err != nil {
		return fmt.Errorf("produce to %s: %w", topic, err)
	}

	sharedkafka.IncProduced(p.service, topic)
	p.log.Debug().Str("topic", topic).Str("key", key).Int("bytes", len(body)).Msg("kafka produce ok")
	return nil
}

// Close flushes pending records and shuts down the underlying kgo.Client.
func (p *Producer) Close(ctx context.Context) error {
	if err := p.client.Flush(ctx); err != nil {
		return err
	}
	p.client.Close()
	return nil
}

// Ping issues an empty metadata request to verify broker reachability.
// Used by /healthz.
func (p *Producer) Ping(ctx context.Context) error {
	return p.client.Ping(ctx)
}
