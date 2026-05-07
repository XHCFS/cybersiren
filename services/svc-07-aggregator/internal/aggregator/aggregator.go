package aggregator

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/saif/cybersiren/services/svc-07-aggregator/internal/metrics"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/observability/tracing"
)

// Publisher is the subset of *kafkaproducer.Producer the aggregator
// uses. Defining it as an interface lets tests substitute a recorder.
type Publisher interface {
	// Publish sends emails.scored; retries = extra attempts after the first.
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// Config holds the runtime knobs; populated from shared/config.
type Config struct {
	HashTTLSecs        int           // Valkey hash TTL on every write (default 120 s)
	TimeoutSecs        int           // Threshold for partial emit (default 30 s)
	SweepInterval      time.Duration // How often the sweeper polls (default 5 s)
	PublishRetries     int           // Inner-loop publish retry budget (default 1)
	PublishLockTTLSecs int           // Valkey NX lock TTL for emissions (default 180 s)
}

// Aggregator is the per-message orchestrator. One instance is shared by
// every consumer goroutine in svckit; methods are safe for concurrent use.
type Aggregator struct {
	cfg       Config
	store     StateStore
	publisher Publisher
	metrics   *metrics.Metrics
	log       zerolog.Logger
	tracer    trace.Tracer
	now       func() time.Time // injectable for tests
}

// New constructs an Aggregator. publisher must be the producer for the
// emails.scored topic.
func New(
	cfg Config,
	store StateStore,
	publisher Publisher,
	m *metrics.Metrics,
	log zerolog.Logger,
) *Aggregator {
	if cfg.HashTTLSecs <= 0 {
		cfg.HashTTLSecs = hashTTLSecs
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = timeoutSecs
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 5 * time.Second
	}
	if cfg.PublishRetries < 0 {
		cfg.PublishRetries = 0
	}
	if cfg.PublishLockTTLSecs <= 0 {
		// Longer than default producer stall window (writes + retries + backoff).
		cfg.PublishLockTTLSecs = 180
	}
	return &Aggregator{
		cfg:       cfg,
		store:     store,
		publisher: publisher,
		metrics:   m,
		log:       log,
		tracer:    tracing.Tracer("svc-07-aggregator"),
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// Handle is the Kafka consumer Handler. It returns nil when the message
// has been processed (offset committable) and a non-nil error only on
// transient infrastructure failures the consumer should retry by NOT
// committing the offset.
//
// Malformed payloads return nil so the offset advances — leaving a poison
// pill blocking the partition forever is worse than skipping it.
func (a *Aggregator) Handle(ctx context.Context, msg kafkaconsumer.Message) error {
	ctx, span := a.tracer.Start(ctx, "aggregator.process", trace.WithAttributes(
		attribute.String("messaging.kafka.topic", msg.Topic),
		attribute.Int("messaging.kafka.partition", msg.Partition),
		attribute.Int64("messaging.kafka.offset", msg.Offset),
	))
	defer span.End()

	emailID, orgID, err := extractIDs(msg.Value)
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		span.RecordError(err)
		span.SetStatus(codes.Error, "malformed payload")
		a.log.Error().Err(err).Str("topic", msg.Topic).Int("partition", msg.Partition).
			Int64("offset", msg.Offset).Msg("malformed payload; skipping")
		return nil
	}
	if emailID == 0 {
		a.observeMessage(msg.Topic, "error")
		span.SetStatus(codes.Error, "payload missing email_id")
		a.log.Warn().Str("topic", msg.Topic).Msg("payload missing email_id; skipping")
		return nil
	}
	span.SetAttributes(
		attribute.Int64("email_id", emailID),
		attribute.Int64("org_id", orgID),
	)

	key := keyForOrgEmail(orgID, emailID)
	field := msg.Topic
	if msg.Topic == contracts.TopicAnalysisPlans {
		field = fieldPlan
	}

	// Persist the message verbatim under the appropriate field. Set
	// __started_at on the first write only (HSETNX is the linearisation
	// point) and keep __org_id current.
	created, err := a.store.HSetIfAbsent(ctx, key, fieldStartedAt, a.now().Format(startedLayout))
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("hsetnx")
		return fmt.Errorf("hsetnx __started_at: %w", err)
	}
	_ = created // information only — no behavioural change today

	if err := a.store.HSet(ctx, key,
		field, string(msg.Value),
		fieldOrgID, strconv.FormatInt(orgID, 10),
	); err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("hset")
		return fmt.Errorf("hset %s: %w", key, err)
	}
	if err := mergePartitionFetchedAt(ctx, a.store, key, msg.Topic, msg.Value); err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("partition_fetched_at")
		return fmt.Errorf("partition fetched_at: %w", err)
	}
	if err := a.store.Expire(ctx, key, a.cfg.HashTTLSecs); err != nil {
		// TTL refresh failure is not fatal — the existing TTL still
		// protects the bucket. Log and continue.
		a.log.Debug().Err(err).Str("key", key).Msg("expire failed; continuing")
	}

	state, err := a.store.HGetAll(ctx, key)
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("hgetall")
		return fmt.Errorf("hgetall %s: %w", key, err)
	}

	complete, hasPlan := completionStatus(state)
	if !hasPlan {
		a.observeMessage(msg.Topic, "wait")
		span.SetAttributes(attribute.String("aggregator.status", "wait_plan"))
		return nil
	}
	if !complete {
		a.observeMessage(msg.Topic, "wait")
		span.SetAttributes(attribute.String("aggregator.status", "wait_scores"))
		return nil
	}

	// Separate Valkey key with short TTL — not a hash field — so a crash
	// after publish cannot leave a permanent lock that blocks retry while
	// the consumer commits.
	lockKey := publishLockKey(orgID, emailID)
	got, err := a.store.SetNXEX(ctx, lockKey, a.cfg.PublishLockTTLSecs, "1")
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("setnx")
		return fmt.Errorf("publish lock setnx: %w", err)
	}
	if !got {
		a.observeMessage(msg.Topic, "wait")
		span.SetAttributes(attribute.String("aggregator.status", "wait_lock"))
		return nil
	}

	startedAt := parseStartedAt(state[fieldStartedAt])
	if pubErr := a.publishAndCleanup(ctx, orgID, emailID, state, startedAt, false /*timeout*/); pubErr != nil {
		_ = a.store.Del(ctx, lockKey)
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("publish")
		span.RecordError(pubErr)
		span.SetStatus(codes.Error, "publish emails.scored failed")
		return pubErr
	}

	a.observeMessage(msg.Topic, "complete")
	span.SetAttributes(attribute.String("aggregator.status", "complete"))
	if a.metrics != nil && !startedAt.IsZero() {
		latency := time.Since(startedAt).Milliseconds()
		a.metrics.CompletionLatencyMS.Observe(float64(latency))
		span.SetAttributes(attribute.Int64("aggregator.completion_latency_ms", latency))
	}
	span.SetStatus(codes.Ok, "")
	return nil
}

// publishAndCleanup serialises the EmailsScored message, publishes to
// Kafka, and (best-effort) deletes the aggregation hash and the publish
// lock key. A delete failure is non-fatal: the hash TTL and lock TTL
// eventually reap stale keys.
func (a *Aggregator) publishAndCleanup(
	ctx context.Context,
	orgID, emailID int64,
	state map[string]string,
	startedAt time.Time,
	timeoutTriggered bool,
) error {
	out, err := packageState(emailID, orgID, state, startedAt, timeoutTriggered)
	if err != nil {
		return fmt.Errorf("package state: %w", err)
	}

	body, err := marshalEmailsScored(out)
	if err != nil {
		return fmt.Errorf("marshal emails.scored: %w", err)
	}

	// PublishRetries = extra kafka attempts after the first ProduceSync.
	key := []byte(strconv.FormatInt(emailID, 10))
	if err := a.publisher.Publish(ctx, key, body, a.cfg.PublishRetries); err != nil {
		return fmt.Errorf("publish emails.scored: %w", err)
	}

	_ = a.store.Del(ctx, publishLockKey(orgID, emailID))

	if err := a.store.Del(ctx, keyForOrgEmail(orgID, emailID)); err != nil {
		// Don't fail the handler — the bucket will TTL out. We just
		// won't accept any further scores for this email_id, which is
		// correct.
		a.log.Debug().Err(err).Int64("email_id", emailID).Msg("aggregator del failed; relying on TTL")
		a.bumpPublishError("del")
	}

	if timeoutTriggered && a.metrics != nil {
		a.metrics.PartialCompletions.Inc()
	}
	return nil
}

func (a *Aggregator) observeMessage(topic, status string) {
	if a == nil || a.metrics == nil || a.metrics.MessagesTotal == nil {
		return
	}
	a.metrics.MessagesTotal.WithLabelValues(topic, status).Inc()
}

func (a *Aggregator) bumpPublishError(kind string) {
	if a == nil || a.metrics == nil || a.metrics.PublishErrors == nil {
		return
	}
	a.metrics.PublishErrors.WithLabelValues(kind).Inc()
}

func parseStartedAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(startedLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// marshalEmailsScored is split out only so tests can stub it. Default
// implementation is the encoding/json package's Marshal.
var marshalEmailsScored = func(v contracts.EmailsScored) ([]byte, error) {
	return jsonMarshal(v)
}

// HandlerFor returns a svckit.Handler binding for the producer in the
// supplied svckit.Deps map. Returns an error wrapper if the producer is
// not configured.
//
// This indirection keeps the cmd/aggregator/main.go free of any direct
// reliance on the svckit package, which mostly helps tests.
func HandlerFor(
	producers map[string]*kafkaproducer.Producer,
	agg *Aggregator,
) (func(ctx context.Context, msg kafkaconsumer.Message) error, error) {
	prod, ok := producers[contracts.TopicEmailsScored]
	if !ok {
		return nil, errors.New("aggregator: producer for emails.scored not configured")
	}
	agg.publisher = prod
	return agg.Handle, nil
}
