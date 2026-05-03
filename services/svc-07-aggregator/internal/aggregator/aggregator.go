package aggregator

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-07-aggregator/internal/metrics"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
)

// Publisher is the subset of *kafkaproducer.Producer the aggregator
// uses. Defining it as an interface lets tests substitute a recorder.
type Publisher interface {
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// Config holds the runtime knobs; populated from shared/config.
type Config struct {
	HashTTLSecs            int           // Valkey hash TTL on every write (default 120 s)
	TimeoutSecs            int           // Threshold for partial emit (default 30 s)
	SweepInterval          time.Duration // How often the sweeper polls (default 5 s)
	PublishRetries         int           // Inner-loop publish retry budget (default 1)
}

// Aggregator is the per-message orchestrator. One instance is shared by
// every consumer goroutine in svckit; methods are safe for concurrent use.
type Aggregator struct {
	cfg        Config
	store      StateStore
	publisher  Publisher
	metrics    *metrics.Metrics
	log        zerolog.Logger
	now        func() time.Time // injectable for tests
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
	return &Aggregator{
		cfg:       cfg,
		store:     store,
		publisher: publisher,
		metrics:   m,
		log:       log,
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
	emailID, orgID, err := extractIDs(msg.Value)
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		a.log.Error().Err(err).Str("topic", msg.Topic).Int("partition", msg.Partition).
			Int64("offset", msg.Offset).Msg("malformed payload; skipping")
		return nil
	}
	if emailID == 0 {
		a.observeMessage(msg.Topic, "error")
		a.log.Warn().Str("topic", msg.Topic).Msg("payload missing email_id; skipping")
		return nil
	}

	key := keyForEmailID(emailID)
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
		return nil
	}
	if !complete {
		a.observeMessage(msg.Topic, "wait")
		return nil
	}

	// Acquire the publish lock so two instances racing on the same email
	// do not double-emit. A lost race returns nil — the winning instance
	// will publish, and the at-least-once semantics of Kafka mean this
	// score message has already been recorded in the hash.
	got, err := a.store.HSetIfAbsent(ctx, key, fieldPublishing, "1")
	if err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("hsetnx")
		return fmt.Errorf("hsetnx __publishing: %w", err)
	}
	if !got {
		a.observeMessage(msg.Topic, "wait")
		return nil
	}

	startedAt := parseStartedAt(state[fieldStartedAt])
	if pubErr := a.publishAndCleanup(ctx, emailID, orgID, state, startedAt, false /*timeout*/); pubErr != nil {
		// Release the publish lock so the redelivered message can retry.
		_ = a.store.HDel(ctx, key, fieldPublishing)
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("publish")
		return pubErr
	}

	a.observeMessage(msg.Topic, "complete")
	if !startedAt.IsZero() {
		a.metrics.CompletionLatencyMS.Observe(float64(time.Since(startedAt).Milliseconds()))
	}
	return nil
}

// publishAndCleanup serialises the EmailsScored message, publishes to
// Kafka, and (best-effort) deletes the Valkey key. A delete failure is
// non-fatal: the at-least-once delivery is already protected by
// __publishing remaining set; the Valkey TTL will reap the key.
func (a *Aggregator) publishAndCleanup(
	ctx context.Context,
	emailID, orgID int64,
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

	if err := a.publisher.Publish(ctx, []byte(strconv.FormatInt(emailID, 10)), body, a.cfg.PublishRetries); err != nil {
		return fmt.Errorf("publish emails.scored: %w", err)
	}

	if err := a.store.Del(ctx, keyForEmailID(emailID)); err != nil {
		// Don't fail the handler — the bucket will TTL out. We just
		// won't accept any further scores for this email_id, which is
		// correct.
		a.log.Debug().Err(err).Int64("email_id", emailID).Msg("aggregator del failed; relying on TTL")
		a.bumpPublishError("del")
	}

	if timeoutTriggered {
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
func HandlerFor(producers map[string]*kafkaproducer.Producer, agg *Aggregator) (func(ctx context.Context, msg kafkaconsumer.Message) error, error) {
	prod, ok := producers[contracts.TopicEmailsScored]
	if !ok {
		return nil, errors.New("aggregator: producer for emails.scored not configured")
	}
	agg.publisher = prod
	return agg.Handle, nil
}
