package engine

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

	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/metrics"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/persist"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/observability/tracing"
)

// Config holds the runtime knobs for the decision engine.
type Config struct {
	BlendWeights         BlendWeights
	Shrinkage            campaign.Shrinkage
	SimHashThreshold     int
	PublishRetryAttempts int
	DefaultModelVersion  string
}

// Defaults applies the v1 starting parameters from the design brief.
func (c Config) Defaults() Config {
	if c.BlendWeights.URL+c.BlendWeights.Header+c.BlendWeights.NLP+c.BlendWeights.Attachment <= 0 {
		c.BlendWeights = DefaultWeights()
	}
	if c.Shrinkage.Tau <= 0 || c.Shrinkage.AlphaMax <= 0 {
		c.Shrinkage = campaign.DefaultShrinkage()
	}
	if c.SimHashThreshold <= 0 {
		c.SimHashThreshold = campaign.SimHashThreshold
	}
	if c.PublishRetryAttempts < 0 {
		c.PublishRetryAttempts = 0
	}
	return c
}

// Publisher is the producer for emails.verdict (subset of
// kafkaproducer.Producer).
type Publisher interface {
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// Engine is the SVC-08 orchestrator. One instance is shared by every
// consumer goroutine; methods are safe for concurrent use.
type Engine struct {
	cfg       Config
	blender   Blender
	rules     *rules.Cache
	evaluator *rules.Evaluator
	simhash   *campaign.Computer
	writer    *persist.Writer
	publisher Publisher
	metrics   *metrics.Metrics
	log       zerolog.Logger
	tracer    trace.Tracer
}

// New constructs an Engine.
func New(
	cfg Config,
	rulesCache *rules.Cache,
	simhash *campaign.Computer,
	writer *persist.Writer,
	publisher Publisher,
	m *metrics.Metrics,
	log zerolog.Logger,
) *Engine {
	cfg = cfg.Defaults()
	return &Engine{
		cfg:       cfg,
		blender:   NewWeightedAverageBlender(cfg.BlendWeights),
		rules:     rulesCache,
		evaluator: rules.NewEvaluator(log),
		simhash:   simhash,
		writer:    writer,
		publisher: publisher,
		metrics:   m,
		log:       log,
		tracer:    tracing.Tracer("svc-08-decision"),
	}
}

// Handle is the Kafka consumer Handler. Returns nil on processed
// (offset committable) and non-nil error on transient infrastructure
// failure (offset NOT committed → message redelivered).
func (e *Engine) Handle(ctx context.Context, msg kafkaconsumer.Message) error {
	startedAt := time.Now()
	defer func() {
		if e.metrics != nil {
			e.metrics.ProcessingDuration.Observe(time.Since(startedAt).Seconds())
		}
	}()

	ctx, span := e.tracer.Start(ctx, "decision.process", trace.WithAttributes(
		attribute.Int("messaging.kafka.partition", msg.Partition),
		attribute.Int64("messaging.kafka.offset", msg.Offset),
	))
	defer span.End()

	scored, err := decodeScored(msg.Value)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "decode failed")
		e.bumpStatus("error")
		e.log.Error().Err(err).
			Int("partition", msg.Partition).Int64("offset", msg.Offset).
			Msg("malformed emails.scored; skipping")
		return nil // commit offset on malformed input — see brief §8 (3)
	}

	logCtx := e.log.With().
		Int64("email_id", scored.Meta.EmailID).
		Int64("org_id", scored.Meta.OrgID).
		Logger()

	span.SetAttributes(
		attribute.Int64("email_id", scored.Meta.EmailID),
		attribute.Int64("org_id", scored.Meta.OrgID),
	)

	// 1. Blend component scores (or fall back to "no ML scores → rule").
	components := ComponentsFrom(scored)
	blendOut := e.blender.Blend(components)
	source := SourceFor(components)

	// 2. Compute fingerprint and (optionally) SimHash. SimHash override
	// hijacks the fingerprint to an existing campaign so the UPSERT
	// appends instead of branching, avoiding orphan campaigns.
	fpInputs := campaign.ExtractInputs(scored.ComponentDetails)
	fingerprint := campaign.Fingerprint(fpInputs)

	var (
		bodyHash  uint64
		hasHash   bool
		simMatch  campaign.Match
		simHit    bool
	)
	if body, ok := campaign.ExtractBody(scored.ComponentDetails); ok {
		bodyHash, hasHash = e.simhash.Compute(body)
		if hasHash {
			match, found, err := e.simhash.Lookup(ctx, scored.Meta.OrgID, bodyHash)
			if err != nil {
				logCtx.Debug().Err(err).Msg("simhash lookup failed; continuing without near-dedup")
			} else if found {
				fingerprint = match.Fingerprint
				simMatch = match
				simHit = true
			}
		}
	}

	// 3. Read campaign history (pre-UPSERT) to drive the empirical-Bayes
	// nudge. A miss returns (nil, nil) — interpreted as "new campaign".
	history, err := e.writer.GetCampaignHistory(ctx, scored.Meta.OrgID, fingerprint)
	if err != nil {
		logCtx.Warn().Err(err).Msg("campaign history lookup failed; proceeding without nudge")
		history = nil
	}
	var campaignHistory *campaign.History
	if history != nil {
		campaignHistory = &campaign.History{
			CampaignID: history.CampaignID,
			RiskScore:  history.RiskScore,
			EmailCount: history.EmailCount,
		}
	}
	nudgedScore, nudgeAlpha := campaign.Nudge(blendOut.Score, campaignHistory, e.cfg.Shrinkage)

	// 4. Load rules and evaluate. Failure → degraded mode (publish a
	// rule-source verdict using just the nudged blend).
	rs, err := e.rules.Get(ctx, scored.Meta.OrgID)
	if err != nil {
		logCtx.Error().Err(err).Msg("decision rules cache load failed; degrading to blend-only verdict")
		return e.publishDegraded(ctx, scored, components, blendOut, nudgedScore, fingerprint, history, simMatch, simHit, hasHash, bodyHash, time.Since(startedAt))
	}

	preRuleLabel := LabelFor(Round(nudgedScore))
	snap := BuildSnapshot(SnapshotInputs{
		Scored:        scored,
		Components:    components,
		BlendedScore:  blendOut.Score,
		NudgedScore:   nudgedScore,
		PreRuleLabel:  preRuleLabel,
		CampaignState: campaignHistory,
	})

	fired, ruleAdjustment := e.evaluator.Evaluate(rs, snap)
	for _, fr := range fired {
		if e.metrics != nil {
			e.metrics.RulesFiredTotal.WithLabelValues(strconv.FormatInt(fr.Rule.ID, 10)).Inc()
		}
	}

	finalScore := ClampInt(Round(nudgedScore)+ruleAdjustment, 0, 100)
	label := LabelFor(finalScore)
	confidence := Confidence(finalScore, label, scored.PartialAnalysis, source)

	// 5. Single-transaction DB write.
	dbStart := time.Now()
	out, err := e.writer.Write(ctx, persist.Input{
		OrgID:      scored.Meta.OrgID,
		InternalID: scored.InternalID,
		FetchedAt:  scored.FetchedAt,

		RiskScore:           finalScore,
		HeaderRiskScore:     scored.HeaderScore,
		ContentRiskScore:    scored.NLPScore,
		URLRiskScore:        scored.URLScore,
		AttachmentRiskScore: scored.AttachmentScore,

		Fingerprint:  fingerprint,
		CampaignName: campaignNameFor(fingerprint),

		Label:         string(label),
		Confidence:    confidence,
		VerdictSource: source,
		ModelVersion:  e.modelVersionFor(scored, source),

		Fired:            fired,
		AnalysisMetadata: marshalAnalysisMetadata(blendOut, nudgedScore, nudgeAlpha, ruleAdjustment, simHit, simMatch),
	})
	if e.metrics != nil {
		e.metrics.DBWriteDuration.Observe(time.Since(dbStart).Seconds())
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "decision tx failed")
		e.bumpStatus("error")
		logCtx.Error().Err(err).Msg("decision tx failed; offset will NOT be committed")
		return err
	}

	if e.metrics != nil {
		if out.IsNew {
			e.metrics.CampaignTotal.WithLabelValues("new").Inc()
		} else {
			e.metrics.CampaignTotal.WithLabelValues("existing").Inc()
		}
	}

	// 6. Best-effort SimHash store (post-commit). Errors are logged
	// only — the verdict is already committed and emitted.
	if hasHash {
		if err := e.simhash.Store(ctx, scored.Meta.OrgID, out.CampaignID, bodyHash, fingerprint); err != nil {
			logCtx.Debug().Err(err).Int64("campaign_id", out.CampaignID).Msg("simhash store failed; index entry skipped")
		}
	}

	// 7. Publish emails.verdict.
	verdict := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
		e.modelVersionFor(scored, source), fired, out, fingerprint, time.Since(startedAt))

	body, err := json.Marshal(verdict)
	if err != nil {
		e.bumpStatus("error")
		span.RecordError(err)
		span.SetStatus(codes.Error, "marshal verdict failed")
		return fmt.Errorf("marshal emails.verdict: %w", err)
	}

	if err := e.publisher.Publish(ctx, encodeKey(scored.Meta.EmailID), body, e.cfg.PublishRetryAttempts); err != nil {
		e.bumpStatus("error")
		span.RecordError(err)
		span.SetStatus(codes.Error, "publish verdict failed")
		return fmt.Errorf("publish emails.verdict: %w", err)
	}

	e.bumpStatus("ok")
	if e.metrics != nil {
		e.metrics.RiskScore.Observe(float64(finalScore))
		e.metrics.VerdictTotal.WithLabelValues(string(label)).Inc()
	}

	logCtx.Info().
		Int("risk_score", finalScore).
		Float64("blended_score", blendOut.Score).
		Float64("nudged_score", nudgedScore).
		Float64("nudge_alpha", nudgeAlpha).
		Int("rule_adjustment", ruleAdjustment).
		Int("fired_rules_count", len(fired)).
		Str("verdict_label", string(label)).
		Float64("confidence", confidence).
		Str("verdict_source", source).
		Bool("is_new_campaign", out.IsNew).
		Bool("simhash_match", simHit).
		Int64("campaign_id", out.CampaignID).
		Int64("duration_ms", time.Since(startedAt).Milliseconds()).
		Msg("decision complete")

	span.SetAttributes(
		attribute.Int("risk_score", finalScore),
		attribute.String("verdict_label", string(label)),
		attribute.Int("fired_rules_count", len(fired)),
	)
	span.SetStatus(codes.Ok, "")
	return nil
}

// publishDegraded handles the rules-cache-load failure path. It still
// computes the verdict from the nudged blend (no rule contribution)
// but flags source=rule and lower confidence. Critically, it still
// runs the single-tx DB write — the verdict must be persisted even if
// rule evaluation was skipped.
func (e *Engine) publishDegraded(
	ctx context.Context,
	scored contracts.EmailsScored,
	components Components,
	blendOut BlendResult,
	nudgedScore float64,
	fingerprint string,
	history *persist.CampaignHistory,
	simMatch campaign.Match,
	simHit bool,
	hasHash bool,
	bodyHash uint64,
	elapsed time.Duration,
) error {
	finalScore := ClampInt(Round(nudgedScore), 0, 100)
	label := LabelFor(finalScore)
	source := VerdictSourceRule
	confidence := Confidence(finalScore, label, scored.PartialAnalysis, source)

	out, err := e.writer.Write(ctx, persist.Input{
		OrgID:      scored.Meta.OrgID,
		InternalID: scored.InternalID,
		FetchedAt:  scored.FetchedAt,

		RiskScore:           finalScore,
		HeaderRiskScore:     scored.HeaderScore,
		ContentRiskScore:    scored.NLPScore,
		URLRiskScore:        scored.URLScore,
		AttachmentRiskScore: scored.AttachmentScore,

		Fingerprint:  fingerprint,
		CampaignName: campaignNameFor(fingerprint),

		Label:         string(label),
		Confidence:    confidence,
		VerdictSource: source,
		ModelVersion:  e.modelVersionFor(scored, source),

		Fired: nil,
		AnalysisMetadata: marshalAnalysisMetadata(
			blendOut, nudgedScore, 0, 0, simHit, simMatch,
		),
	})
	if err != nil {
		e.bumpStatus("error")
		return err
	}

	if hasHash {
		_ = e.simhash.Store(ctx, scored.Meta.OrgID, out.CampaignID, bodyHash, fingerprint)
	}

	verdict := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
		e.modelVersionFor(scored, source), nil, out, fingerprint, elapsed)
	body, err := json.Marshal(verdict)
	if err != nil {
		return err
	}
	if err := e.publisher.Publish(ctx, encodeKey(scored.Meta.EmailID), body, e.cfg.PublishRetryAttempts); err != nil {
		e.bumpStatus("error")
		return err
	}
	e.bumpStatus("ok")
	if e.metrics != nil {
		e.metrics.RiskScore.Observe(float64(finalScore))
		e.metrics.VerdictTotal.WithLabelValues(string(label)).Inc()
		if out.IsNew {
			e.metrics.CampaignTotal.WithLabelValues("new").Inc()
		} else {
			e.metrics.CampaignTotal.WithLabelValues("existing").Inc()
		}
	}
	_ = history // suppressed: logged through persist write inputs already
	return nil
}

func (e *Engine) modelVersionFor(_ contracts.EmailsScored, source string) string {
	if source == VerdictSourceRule {
		return ""
	}
	return e.cfg.DefaultModelVersion
}

func (e *Engine) bumpStatus(status string) {
	if e == nil || e.metrics == nil || e.metrics.MessagesTotal == nil {
		return
	}
	e.metrics.MessagesTotal.WithLabelValues(status).Inc()
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func decodeScored(b []byte) (contracts.EmailsScored, error) {
	var out contracts.EmailsScored
	if len(b) == 0 {
		return out, errors.New("empty payload")
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("unmarshal emails.scored: %w", err)
	}
	if out.Meta.EmailID <= 0 {
		return out, fmt.Errorf("emails.scored: meta.email_id must be > 0, got %d", out.Meta.EmailID)
	}
	return out, nil
}

func encodeKey(emailID int64) []byte {
	return []byte(strconv.FormatInt(emailID, 10))
}

// campaignNameFor builds a placeholder human-readable name for new
// campaigns when the engine has no better information. SVC-04 / a
// future dashboard can rename it later.
func campaignNameFor(fingerprint string) string {
	if len(fingerprint) >= 12 {
		return "campaign-" + fingerprint[:12]
	}
	return "campaign-" + fingerprint
}

// marshalAnalysisMetadata builds the JSONB blob written to
// emails.analysis_metadata for explainability. Per design brief §3.4,
// component contributions are preserved here regardless of blending
// method; the blob also records the campaign-nudge details.
func marshalAnalysisMetadata(
	blendOut BlendResult,
	nudgedScore float64,
	nudgeAlpha float64,
	ruleAdjustment int,
	simHit bool,
	simMatch campaign.Match,
) []byte {
	meta := map[string]any{
		"blend": map[string]any{
			"score":         blendOut.Score,
			"weight_sum":    blendOut.WeightSum,
			"contributions": blendOut.Contributions,
		},
		"nudge": map[string]any{
			"alpha": nudgeAlpha,
			"score": nudgedScore,
		},
		"rule_adjustment": ruleAdjustment,
	}
	if simHit {
		meta["simhash"] = map[string]any{
			"matched":           true,
			"matched_campaign":  simMatch.CampaignID,
			"hamming_distance":  simMatch.Distance,
		}
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	return body
}

// buildVerdict assembles the emails.verdict wire message.
func buildVerdict(
	scored contracts.EmailsScored,
	finalScore int,
	components Components,
	blendOut BlendResult,
	label Label,
	confidence float64,
	source string,
	modelVersion string,
	fired []rules.FiredRule,
	out persist.Output,
	fingerprint string,
	elapsed time.Duration,
) contracts.EmailsVerdict {
	_ = blendOut // reserved for future serialisation; analysis_metadata holds the breakdown
	wireFired := make([]contracts.VerdictFiredRule, 0, len(fired))
	for _, fr := range fired {
		wireFired = append(wireFired, contracts.VerdictFiredRule{
			RuleID:      fr.Rule.ID,
			RuleName:    fr.Rule.Name,
			ScoreImpact: fr.Rule.ScoreImpact,
		})
	}
	campID := out.CampaignID
	verdict := contracts.EmailsVerdict{
		Meta:                  contracts.NewMeta(scored.Meta.EmailID, scored.Meta.OrgID),
		InternalID:            scored.InternalID,
		FetchedAt:             scored.FetchedAt,
		VerdictLabel:          string(label),
		Confidence:            confidence,
		RiskScore:             finalScore,
		HeaderRiskScore:       components.Header,
		ContentRiskScore:      components.NLP,
		URLRiskScore:          components.URL,
		AttachmentRiskScore:   components.Attachment,
		CampaignID:            &campID,
		CampaignFingerprint:   fingerprint,
		IsNewCampaign:         out.IsNew,
		FiredRules:            wireFired,
		VerdictSource:         source,
		ModelVersion:          modelVersion,
		PartialAnalysis:       scored.PartialAnalysis,
		ProcessingTimeTotalMS: elapsed.Milliseconds(),
	}
	return verdict
}
