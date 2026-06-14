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
	// TombstoneFinalized, when true (default), writes a short-TTL tombstone on
	// finalization so late component scores are dropped instead of resurrecting
	// a plan-less bucket (P1). Exposed so ops can disable the gate if needed.
	// Set it via SetTombstoneFinalized so New can tell "left at zero value"
	// (→ default ON) from an explicit disable.
	TombstoneFinalized bool
	tombstoneSet       bool // true once SetTombstoneFinalized was called
}

// SetTombstoneFinalized explicitly sets the P1 tombstone gate, marking the
// field as deliberately configured so New does not override it with the
// default-ON value. Used by main.go (env override) and tests.
func (c *Config) SetTombstoneFinalized(v bool) {
	c.TombstoneFinalized = v
	c.tombstoneSet = true
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
	// Tombstone gate defaults ON; main.go reads CYBERSIREN_AGGREGATOR__TOMBSTONE
	// to disable it explicitly. The zero value of Config (used by some tests)
	// thus gets the P1 protection by default — matching production wiring.
	if !cfg.tombstoneSet {
		cfg.TombstoneFinalized = true
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
	if emailID == "" {
		a.observeMessage(msg.Topic, "error")
		span.SetStatus(codes.Error, "payload missing email_id")
		a.log.Warn().Str("topic", msg.Topic).Msg("payload missing email_id; skipping")
		return nil
	}
	span.SetAttributes(
		attribute.String("email_id", emailID),
		attribute.Int64("org_id", orgID),
	)

	key := keyForOrgEmail(orgID, emailID)
	field := msg.Topic
	if msg.Topic == contracts.TopicAnalysisPlans {
		field = fieldPlan
	}

	// P1 — Tombstone gate. If this email_id was already finalized (emails.scored
	// emitted and the bucket Del'd), a tombstone with the bucket TTL is present.
	// A score arriving now is "late": its plan field is gone forever (Kafka
	// offset committed, never redelivered), so (re)creating a bucket here would
	// produce a plan-less zombie that the sweeper re-logs every tick until TTL.
	// Drop the late score cleanly instead. We deliberately DISCARD rather than
	// re-emit a corrected partial: svc-08 keys idempotency on (internal_id,
	// fetched_at) and dedupe-skips a second emails.scored for an already-written
	// verdict (persist/writer.go FindExistingVerdictForEmail → DedupeSkip), so a
	// re-emit would not update the verdict — it would be silently swallowed.
	// Correcting late scores is a follow-up that needs svc-08 to recompute on
	// replay; see the audit's svc-03 P0 for the real fix (land URL scores in time).
	if a.cfg.TombstoneFinalized {
		if done, terr := a.store.Exists(ctx, tombstoneKey(orgID, emailID)); terr != nil {
			// Treat a tombstone-probe failure as "unknown" and fall through:
			// at worst we recreate a bucket the sweeper will age out, which is
			// the pre-tombstone behaviour — never NACK on this best-effort gate.
			a.log.Debug().Err(terr).Str("email_id", emailID).Msg("tombstone probe failed; continuing")
		} else if done {
			a.observeMessage(msg.Topic, "late_drop")
			a.bumpLateDrop("after_finalization")
			a.log.Debug().Str("topic", msg.Topic).Str("email_id", emailID).Int64("org_id", orgID).
				Msg("dropping late score: email_id already finalized (tombstoned)")
			span.SetAttributes(attribute.String("aggregator.status", "late_drop_tombstoned"))
			return nil
		}
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
	if err := mergePartitionInternalID(ctx, a.store, key, msg.Topic, msg.Value); err != nil {
		a.observeMessage(msg.Topic, "error")
		a.bumpPublishError("partition_internal_id")
		return fmt.Errorf("partition internal_id: %w", err)
	}
	if err := a.store.Expire(ctx, key, a.cfg.HashTTLSecs); err != nil {
		if created {
			// First write for this bucket: Expire is the ONLY thing that
			// ever applies a TTL, and it just failed — the hash was created
			// TTL-less. Committing now would leak the key in Valkey forever
			// (the sweeper's no-plan path only Dels the lock and relies on
			// the hash TTLing out). NACK so the offset is not committed and
			// the message redelivers, guaranteeing the bucket gets a TTL.
			a.observeMessage(msg.Topic, "error")
			a.bumpPublishError("expire")
			return fmt.Errorf("expire %s on first write: %w", key, err)
		}
		// Subsequent write: a prior write already set the TTL, so a refresh
		// failure is not fatal — the existing TTL still protects the bucket.
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
	// The bucket is complete, but a concurrent scores.header handler may not
	// have merged __partition_internal_id yet (HSET field then HSETNX id are
	// two ops). Publishing now would resolve internal_id=0 (there is NO email_id
	// fallback — LANDMINE B), yielding an unaddressable verdict the producer
	// would have to drop. Wait for the id to land — a later arrival or the
	// scores.header handler itself re-triggers; the timeout sweeper is the backstop.
	if internalIDPending(state) {
		a.observeMessage(msg.Topic, "wait")
		span.SetAttributes(attribute.String("aggregator.status", "wait_internal_id"))
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
		// Lost the publish lock — the sweeper (or another instance) holds it.
		// If it captured a PARTIAL snapshot before this completing score was
		// visible, committing now would silently DROP this arrived component:
		// the sweeper publishes the partial, Dels the hash, and this score is
		// gone with no re-emit path. Re-read the bucket: while it is still
		// present AND complete, the holder has not yet published+deleted, so
		// NACK to redeliver and re-contend for the lock. Once the bucket is
		// gone (holder published+deleted) the complete result is unrecoverable
		// (the plan field was deleted with the hash); at that point committing
		// is correct — at-least-once is satisfied and there is nothing left to
		// publish for this email_id.
		if again, gerr := a.store.HGetAll(ctx, key); gerr == nil {
			if stillComplete, hasPlan := completionStatus(again); hasPlan && stillComplete {
				a.observeMessage(msg.Topic, "error")
				a.bumpPublishError("wait_lock_complete")
				span.SetAttributes(attribute.String("aggregator.status", "wait_lock_retry"))
				return fmt.Errorf("publish lock held while bucket %s still complete; retrying", key)
			}
		}
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
	orgID int64,
	emailID string,
	state map[string]string,
	startedAt time.Time,
	timeoutTriggered bool,
) error {
	out, err := packageState(emailID, orgID, state, startedAt, timeoutTriggered)
	if err != nil {
		return fmt.Errorf("package state: %w", err)
	}

	// Defense-in-depth: a resolved internal_id of 0 (no scores.header forwarded
	// svc-02's BIGSERIAL id) means the message cannot be addressed to a DB verdict
	// row — there is NO email_id fallback (LANDMINE B), and svc-08 would silently
	// discard it (decodeScored rejects internal_id<=0 and commits the offset). So
	// we make the drop loud here and SKIP the emit rather than ship a poison
	// record. EmailsScored.Validate also guards InternalID>0 plus score ranges.
	// This is an observable skip, not a NACK: looping forever cannot conjure an
	// id that upstream never produced. We still tear down the bucket+lock so the
	// dead email_id does not linger and re-fire.
	if vErr := out.Validate(); vErr != nil {
		a.log.Error().Err(vErr).
			Str("email_id", emailID).Int64("org_id", orgID).Int64("internal_id", out.InternalID).
			Msg("cannot emit emails.scored: internal_id unresolved — dropping; verdict cannot be addressed")
		a.bumpPublishError("internal_id_unresolved")
		a.bumpLateDrop("internal_id_unresolved")
		// Tombstone first: this email_id is finalized-as-dropped, so any late
		// score must not resurrect a (plan-less) zombie bucket either.
		a.writeTombstone(ctx, orgID, emailID)
		_ = a.store.Del(ctx, publishLockKey(orgID, emailID))
		if err := a.store.Del(ctx, keyForOrgEmail(orgID, emailID)); err != nil {
			a.log.Debug().Err(err).Str("email_id", emailID).Msg("aggregator del failed; relying on TTL")
			a.bumpPublishError("del")
		}
		return nil
	}

	body, err := marshalEmailsScored(out)
	if err != nil {
		return fmt.Errorf("marshal emails.scored: %w", err)
	}

	// PublishRetries = extra kafka attempts after the first ProduceSync.
	key := []byte(emailID)
	if err := a.publisher.Publish(ctx, key, body, a.cfg.PublishRetries); err != nil {
		return fmt.Errorf("publish emails.scored: %w", err)
	}

	// Tombstone this email_id BEFORE deleting the bucket so a late score that
	// races in between cannot recreate a plan-less zombie (P1). Best-effort:
	// on tombstone failure the worst case is the pre-fix behaviour.
	a.writeTombstone(ctx, orgID, emailID)

	_ = a.store.Del(ctx, publishLockKey(orgID, emailID))

	if err := a.store.Del(ctx, keyForOrgEmail(orgID, emailID)); err != nil {
		// Don't fail the handler — the bucket will TTL out. We just
		// won't accept any further scores for this email_id, which is
		// correct.
		a.log.Debug().Err(err).Str("email_id", emailID).Msg("aggregator del failed; relying on TTL")
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

// writeTombstone marks an email_id as finalized so Handle's tombstone gate
// drops late scores instead of resurrecting a plan-less bucket. TTL matches
// the bucket TTL: late scores can only arrive within that window (their own
// bucket would otherwise have TTL'd out), and a longer-lived tombstone would
// needlessly suppress a legitimately-new same-email_id (which cannot happen
// for UUIDv7 ids anyway). Best-effort: a write failure is logged, not fatal.
func (a *Aggregator) writeTombstone(ctx context.Context, orgID int64, emailID string) {
	if !a.cfg.TombstoneFinalized {
		return
	}
	if err := a.store.SetEX(ctx, tombstoneKey(orgID, emailID), a.cfg.HashTTLSecs, "1"); err != nil {
		a.log.Debug().Err(err).Str("email_id", emailID).Msg("tombstone write failed; late scores may recreate a bucket")
	}
}

func (a *Aggregator) bumpLateDrop(reason string) {
	if a == nil || a.metrics == nil || a.metrics.LateDrops == nil {
		return
	}
	a.metrics.LateDrops.WithLabelValues(reason).Inc()
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
