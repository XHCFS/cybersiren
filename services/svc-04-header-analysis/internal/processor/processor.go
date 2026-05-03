package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	sharedproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/observability/tracing"
)

// Config wires the processor's runtime parameters.
type Config struct {
	HopCountThreshold       int
	TimeDriftHoursThreshold float64
	TyposquatMaxDistance    int
	ScoringBlend            string
	AuthWeight              float64
	ReputationWeight        float64
	StructuralWeight        float64
	PublishRetryAttempts    int
}

// Processor is the per-message orchestrator. It is constructed once at
// startup and then invoked from the Kafka consumer Run loop.
type Processor struct {
	cfg Config

	rules      *rules.Cache
	evaluator  *rules.Evaluator
	reputation *header.ReputationExtractor
	writer     *RuleHitWriter
	producer   *sharedproducer.Producer

	metrics *Metrics
	log     zerolog.Logger
	tracer  trace.Tracer
}

// New constructs a Processor.
func New(
	cfg Config,
	rulesCache *rules.Cache,
	reputation *header.ReputationExtractor,
	writer *RuleHitWriter,
	producer *sharedproducer.Producer,
	metrics *Metrics,
	log zerolog.Logger,
) *Processor {
	return &Processor{
		cfg:        cfg,
		rules:      rulesCache,
		evaluator:  rules.NewEvaluator(log),
		reputation: reputation,
		writer:     writer,
		producer:   producer,
		metrics:    metrics,
		log:        log,
		tracer:     tracing.Tracer("svc-04-header-analysis"),
	}
}

// Handle is the Kafka consumer Handler. Returning a non-nil error tells
// the consumer NOT to commit the offset (the message is redelivered).
func (p *Processor) Handle(ctx context.Context, msg sharedconsumer.Message) error {
	startedAt := time.Now()
	defer func() {
		p.metrics.Duration.Observe(time.Since(startedAt).Seconds())
	}()

	ctx, span := p.tracer.Start(ctx, "header.process",
		trace.WithAttributes(
			attribute.Int("messaging.kafka.partition", msg.Partition),
			attribute.Int64("messaging.kafka.offset", msg.Offset),
		),
	)
	defer span.End()

	parsed, err := decodeMessage(msg.Value)
	if err != nil {
		// Malformed message: increment metric and return nil so the
		// offset commits — re-delivery would just yield the same parse
		// failure forever and block the partition.
		p.observeError("consume")
		span.RecordError(err)
		span.SetStatus(codes.Error, "decode failed")
		p.log.Error().Err(err).
			Int("partition", msg.Partition).
			Int64("offset", msg.Offset).
			Msg("malformed analysis.headers message; skipping")
		p.metrics.MessagesTotal.WithLabelValues("error").Inc()
		return nil
	}

	span.SetAttributes(
		attribute.Int64("email_id", parsed.EmailID),
		attribute.Int64("org_id", parsed.OrgID),
	)

	logCtx := p.log.With().
		Int64("email_id", parsed.EmailID).
		Int64("org_id", parsed.OrgID).
		Logger()
	if sc := msg.SpanContext; sc.IsValid() {
		logCtx = logCtx.With().Str("trace_id", sc.TraceID().String()).Logger()
	}

	cachedRules, err := p.rules.Get(ctx, parsed.OrgID)
	if err != nil {
		p.observeError("rules_load")
		span.RecordError(err)
		span.SetStatus(codes.Error, "rules load failed")
		logCtx.Error().Err(err).Msg("rules cache load failed")
		p.metrics.MessagesTotal.WithLabelValues("error").Inc()
		// Don't redeliver: a DB blip should be observable but should not
		// block downstream processing indefinitely. We emit a neutral
		// score (0) so SVC-07 can complete its 5-component aggregation.
		return p.publishNeutral(ctx, parsed, time.Since(startedAt))
	}

	signals := header.HeaderSignals{
		Auth:       header.ExtractAuth(&parsed),
		Reputation: p.reputation.Extract(ctx, &parsed),
		Structural: header.ExtractStructural(&parsed, header.StructuralExtractorConfig{
			HopCountThreshold:       p.cfg.HopCountThreshold,
			TimeDriftHoursThreshold: p.cfg.TimeDriftHoursThreshold,
		}),
		Source: &parsed,
	}

	snapshot := rules.SignalsToSnapshot(signals)
	evalResult := p.evaluator.Evaluate(cachedRules, snapshot)

	finalScore := rules.FinalScore(
		evalResult.AuthSubScore,
		evalResult.ReputationSubScore,
		evalResult.StructuralSubScore,
		p.cfg.ScoringBlend,
		p.cfg.AuthWeight, p.cfg.ReputationWeight, p.cfg.StructuralWeight,
	)

	for _, fr := range evalResult.Fired {
		p.metrics.RulesFiredTotal.WithLabelValues(strconv.FormatInt(fr.Rule.ID, 10)).Inc()
	}

	// Persist before publishing — ARCH-SPEC §6 requires that offset is
	// only committed after rule_hits commit success.
	outcome, writeErr := p.writer.Write(ctx, parsed.EmailID, parsed.FetchedAt, evalResult.Fired)
	p.metrics.WriteRetries.WithLabelValues(outcome).Inc()
	if writeErr != nil {
		p.observeError("db_write")
		span.RecordError(writeErr)
		span.SetStatus(codes.Error, "rule_hits write failed")
		logCtx.Error().Err(writeErr).Int("fired_rules", len(evalResult.Fired)).
			Msg("rule_hits write failed; offset will NOT be committed")
		p.metrics.MessagesTotal.WithLabelValues("error").Inc()
		// Returning a non-nil error keeps the offset un-committed. Note
		// that segmentio/kafka-go advances FetchMessage even when the
		// handler errors, so the failed message will only be re-read
		// after consumer restart or partition rebalance. The bounded
		// retry-with-backoff inside RuleHitWriter is therefore the
		// in-process retry path; this branch only triggers after that
		// budget is exhausted.
		return writeErr
	}

	out := buildScoresHeader(parsed, signals, evalResult, finalScore, time.Since(startedAt))

	body, err := json.Marshal(out)
	if err != nil {
		p.observeError("publish")
		span.RecordError(err)
		span.SetStatus(codes.Error, "marshal scores.header failed")
		logCtx.Error().Err(err).Msg("marshal scores.header failed")
		p.metrics.MessagesTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("marshal scores.header: %w", err)
	}

	if err := p.producer.Publish(ctx, encodeKey(parsed.EmailID), body, p.cfg.PublishRetryAttempts); err != nil { // extra kafka retries cfg
		p.observeError("publish")
		span.RecordError(err)
		span.SetStatus(codes.Error, "publish scores.header failed")
		logCtx.Error().Err(err).Msg("publish scores.header failed")
		p.metrics.MessagesTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("publish scores.header: %w", err)
	}

	p.metrics.MessagesTotal.WithLabelValues("ok").Inc()
	p.metrics.ScoreTotal.WithLabelValues(ScoreBucket(finalScore)).Inc()

	logCtx.Info().
		Int("score", finalScore).
		Int("auth_sub_score", evalResult.AuthSubScore).
		Int("reputation_sub_score", evalResult.ReputationSubScore).
		Int("structural_sub_score", evalResult.StructuralSubScore).
		Int("fired_rules_count", len(evalResult.Fired)).
		Int64("duration_ms", time.Since(startedAt).Milliseconds()).
		Msg("header analysis complete")

	span.SetAttributes(
		attribute.Int("score", finalScore),
		attribute.Int("fired_rules_count", len(evalResult.Fired)),
	)
	span.SetStatus(codes.Ok, "")
	return nil
}

func (p *Processor) publishNeutral(ctx context.Context, parsed contractsk.AnalysisHeadersMessage, elapsed time.Duration) error {
	out := buildScoresHeader(parsed, header.HeaderSignals{}, rules.EvaluationResult{}, 0, elapsed)
	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal neutral scores.header: %w", err)
	}
	if err := p.producer.Publish(ctx, encodeKey(parsed.EmailID), body, p.cfg.PublishRetryAttempts); err != nil { // extra kafka retries cfg
		p.observeError("publish")
		return fmt.Errorf("publish neutral scores.header: %w", err)
	}
	p.metrics.MessagesTotal.WithLabelValues("ok").Inc()
	return nil
}

func decodeMessage(body []byte) (contractsk.AnalysisHeadersMessage, error) {
	var out contractsk.AnalysisHeadersMessage
	if len(body) == 0 {
		return out, errors.New("empty kafka payload")
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("unmarshal analysis.headers: %w", err)
	}
	if out.EmailID <= 0 {
		return out, fmt.Errorf("analysis.headers email_id must be > 0, got %d", out.EmailID)
	}
	if out.FetchedAt.IsZero() {
		return out, errors.New("analysis.headers fetched_at is required")
	}
	return out, nil
}

func encodeKey(emailID int64) []byte {
	return []byte(strconv.FormatInt(emailID, 10))
}

func buildScoresHeader(
	parsed contractsk.AnalysisHeadersMessage,
	signals header.HeaderSignals,
	evalResult rules.EvaluationResult,
	finalScore int,
	elapsed time.Duration,
) contractsk.ScoresHeaderMessage {
	wireFired := make([]contractsk.FiredRule, 0, len(evalResult.Fired))
	for _, fr := range evalResult.Fired {
		wireFired = append(wireFired, contractsk.FiredRule{
			RuleID:      fr.Rule.ID,
			RuleName:    fr.Rule.Name,
			RuleVersion: fr.Rule.Version,
			ScoreImpact: fr.Rule.ScoreImpact,
			MatchDetail: fr.MatchDetail,
		})
	}

	return contractsk.ScoresHeaderMessage{
		EmailID:            parsed.EmailID,
		OrgID:              parsed.OrgID,
		Component:          "header",
		Score:              finalScore,
		AuthSubScore:       evalResult.AuthSubScore,
		ReputationSubScore: evalResult.ReputationSubScore,
		StructuralSubScore: evalResult.StructuralSubScore,
		FiredRules:         wireFired,
		Signals:            signals.AsContract(),
		ProcessingTimeMs:   int(elapsed.Milliseconds()),
	}
}

func (p *Processor) observeError(stage string) {
	if p == nil || p.metrics == nil || p.metrics.ErrorsTotal == nil {
		return
	}
	p.metrics.ErrorsTotal.WithLabelValues(stage).Inc()
}
