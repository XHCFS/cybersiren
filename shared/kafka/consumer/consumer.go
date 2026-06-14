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
	"os"
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

// maxHandlerRetries bounds how many consecutive times the SAME record may fail
// its handler before the consumer gives up on it. Transient failures that
// recover within this many polls are retried as before (at-least-once); a
// permanently-failing ("poison") record is dead-lettered (logged) and its
// offset committed so the partition advances instead of stalling forever.
const maxHandlerRetries = 8

// retryBackoff is the minimum delay inserted before a partition is re-fetched
// after a handler error, so a fast-failing poison record does not spin the poll
// loop while it burns through its retry budget.
const retryBackoff = 200 * time.Millisecond

// commitEvery bounds how many successfully-processed records accumulate before
// the consumer commits, so draining a large backlog cannot spend minutes in a
// single poll batch without advancing the committed offset (which would leave
// the consumer reprocessing the same records and never making durable progress).
const commitEvery = 200

// Handler processes a single Kafka message and returns nil on success.
//
// On a non-nil error the consumer logs the failure, increments error metrics,
// and does NOT commit the record's offset: the partition is rewound to the
// failed record so it (and the records after it) are re-fetched and retried on
// the next poll (at-least-once). To stop a permanently-failing record from
// stalling its partition indefinitely, the same record is retried at most
// maxHandlerRetries times; past that it is dead-lettered (structured ERROR log)
// and its offset committed so the partition advances.
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

// stuckRecord tracks the consecutive failure count for the single record that
// is currently blocking a partition. We only ever keep one entry per partition
// (the head record that keeps failing); it is replaced when the head offset
// advances and removed when the partition succeeds, so this map cannot grow
// unbounded.
type stuckRecord struct {
	offset   int64
	failures int
}

// Consumer is a single-topic at-least-once Kafka consumer.
type Consumer struct {
	client      *kgo.Client
	tracer      *kotel.Tracer
	cfg         Config
	pollTimeout time.Duration
	log         zerolog.Logger

	// retries tracks the currently-stuck record per partition so a poison
	// message can be bounded and dead-lettered rather than retried forever.
	// Run is single-goroutine, so no locking is required.
	retries map[int32]*stuckRecord

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
		// Surface franz-go's own group-coordination / commit problems (rebalances,
		// commit failures) which are otherwise invisible. WARN keeps it quiet in
		// steady state.
		kgo.WithLogger(kgo.BasicLogger(os.Stderr, kgo.LogLevelWarn, nil)),
	)
	if err != nil {
		return nil, fmt.Errorf("kafka consumer: %w", err)
	}

	c := &Consumer{
		client:      cli,
		tracer:      tracer,
		cfg:         cfg,
		pollTimeout: cfg.PollTimeout,
		retries:     make(map[int32]*stuckRecord),
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

		// Process records grouped by partition so a handler failure rewinds ONLY
		// the offending partition. We commit the contiguous successful PREFIX of
		// each partition; on the first handler error in a partition we rewind the
		// consume position to that record (SetOffsets) and stop processing the
		// partition, so the failed record — and everything after it — is re-fetched
		// and retried rather than skipped. franz-go advances the fetch cursor to the
		// batch tail at poll time, so the previous code (skip-commit-on-any-error +
		// CommitUncommittedOffsets) silently DROPPED a failed offset the moment a
		// later batch committed the cumulative head — i.e. every fail-secure NACK in
		// the pipeline lost its message instead of redelivering. A permanently
		// failing ("poison") record now stalls its partition until it succeeds; the
		// bounded-retry + dead-letter escape is the deferred platform task (§16 D16
		// / P8 8a-v).
		var toCommit []*kgo.Record
		needsBackoff := false
		fetches.EachPartition(func(ftp kgo.FetchTopicPartition) {
			if ftp.Err != nil {
				c.observeError(ftp.Topic, c.cfg.GroupID, "fetch")
				c.log.Error().Err(ftp.Err).Str("topic", ftp.Topic).
					Int32("partition", ftp.Partition).Msg("partition fetch error")
				return
			}
			for _, rec := range ftp.Records {
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

					// Track consecutive failures of THIS record so a permanently
					// failing ("poison") record cannot stall the partition forever.
					fails := c.recordFailure(rec.Partition, rec.Offset)

					if fails > maxHandlerRetries {
						// Poison record: give up retrying, dead-letter it (structured
						// ERROR log; this codebase has no DLQ topic convention), commit
						// its offset so the partition advances, and continue processing
						// the records after it.
						recLog.Error().Err(err).
							Int("failures", fails).
							Int("max_retries", maxHandlerRetries).
							Msg("kafka handler error budget exhausted; dead-lettering poison message and committing offset to advance partition")
						c.observeError(c.cfg.Topic, c.cfg.GroupID, "deadletter")
						c.clearFailure(rec.Partition)
						span.RecordError(err)
						span.End()
						toCommit = append(toCommit, rec)
						continue // skip this record; keep processing the partition
					}

					recLog.Error().Err(err).
						Int("failures", fails).
						Int("max_retries", maxHandlerRetries).
						Msg("kafka handler error; rewinding partition to retry (offset not committed)")
					// Rewind this partition to the failed record (carrying the leader
					// epoch so the reset is fenced) so it and the records after it are
					// re-fetched on the next poll.
					c.client.SetOffsets(map[string]map[int32]kgo.EpochOffset{
						rec.Topic: {rec.Partition: {Epoch: rec.LeaderEpoch, Offset: rec.Offset}},
					})
					needsBackoff = true
					span.RecordError(err)
					span.End()
					return // stop this partition; records after the failure are not processed
				}

				// Success: clear any retry state for this partition so a later
				// transient failure starts from a fresh budget.
				c.clearFailure(rec.Partition)
				sharedkafka.IncConsumed(c.cfg.GroupID, rec.Topic)
				c.observeMessages(c.cfg.Topic, c.cfg.GroupID, "ok")
				c.observeProcessingLatency(c.cfg.Topic, c.cfg.GroupID, time.Since(start))
				toCommit = append(toCommit, rec)
				span.End()

				// Commit incrementally so a single large poll batch (e.g. when
				// draining a backlog) cannot process for minutes without ever
				// advancing the committed offset. Without this, the offset only
				// moves once the WHOLE batch finishes, so a big backlog leaves the
				// consumer reprocessing the same records on every restart and never
				// makes durable progress.
				if len(toCommit) >= commitEvery {
					c.commitBatch(ctx, toCommit)
					toCommit = toCommit[:0]
				}
			}
		})

		if needsBackoff {
			// Brief pause before re-fetching a rewound partition so a fast-failing
			// record does not spin the poll loop while it burns its retry budget.
			select {
			case <-ctx.Done():
			case <-time.After(retryBackoff):
			}
		}

		if len(toCommit) > 0 {
			c.commitBatch(ctx, toCommit)
		}
	}
}

// commitBatch synchronously commits the given successfully-processed records on
// a shutdown-independent context so the batch is not dropped when ctx is already
// cancelled by SIGTERM (a dropped commit reprocesses the batch on the next
// restart). Commit failures are logged + metered but not fatal.
func (c *Consumer) commitBatch(_ context.Context, recs []*kgo.Record) {
	if len(recs) == 0 {
		return
	}
	commitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.client.CommitRecords(commitCtx, recs...); err != nil {
		c.observeError(c.cfg.Topic, c.cfg.GroupID, "commit")
		c.log.Error().Err(err).Msg("commit offsets failed")
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
	if err := c.client.Ping(ctx); err != nil {
		return fmt.Errorf("kafka consumer ping: %w", err)
	}
	return nil
}

// recordFailure increments and returns the consecutive-failure count for the
// record at (partition, offset). If the tracked offset for the partition has
// advanced (a different record is now stuck, or the previous one was
// dead-lettered) the count resets to 1. Only the current head record per
// partition is tracked, so the map size is bounded by the partition count.
func (c *Consumer) recordFailure(partition int32, offset int64) int {
	if sr, ok := c.retries[partition]; ok && sr.offset == offset {
		sr.failures++
		return sr.failures
	}
	c.retries[partition] = &stuckRecord{offset: offset, failures: 1}
	return 1
}

// clearFailure drops any tracked failure state for a partition. Called on
// success and after a record is dead-lettered.
func (c *Consumer) clearFailure(partition int32) {
	delete(c.retries, partition)
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
