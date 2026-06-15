package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// FusionMode selects which Blender combines the per-component scores.
const (
	// FusionWeightedAverage is the v1 weighted mean (design brief §3.4).
	FusionWeightedAverage = "weighted_average"
	// FusionNoisyOR is the hand-set reliability probabilistic-OR blender (see
	// noisyor_blender.go): never dilutes a confident channel but uses hand-set
	// reliabilities. Kept as a rollback/shadow.
	FusionNoisyOR = "noisy_or"
	// FusionCalibratedOR is the calibrated probabilistic-OR blender (see
	// calibrated_blender.go): per-channel learned calibration → OR → final
	// calibration. It is the production fusion — on the consistent real-model base
	// it scores 83.5% recall@1%FPR (vs weighted_average 58.4%, NLP-alone 79.4%) and
	// is well calibrated (ECE ≈ 0.005) so the §3.6 bands hold. See benchmark/FINDINGS.md.
	FusionCalibratedOR = "calibrated_or"
)

// Config holds the runtime knobs for the decision engine.
type Config struct {
	// FusionMode selects the Blender. Empty defaults to FusionWeightedAverage so
	// existing callers keep v1 behaviour; the service sets FusionNoisyOR explicitly.
	FusionMode string
	// FusionShadow, when true, also computes the *other* fusion method per email and
	// records verdict-band disagreement (decision_fusion_shadow_disagree_total) so
	// the impact of switching can be measured before it is enabled. It never gates a
	// verdict. Default false — steady-state deployments that are not running a
	// fusion-calibration study pay nothing for the second blend.
	FusionShadow         bool
	BlendWeights         BlendWeights
	Reliabilities        Reliabilities
	Shrinkage            campaign.Shrinkage
	SimHashThreshold     int
	PublishRetryAttempts int
	DefaultModelVersion  string
}

// Defaults applies the v1 starting parameters from the design brief.
func (c Config) Defaults() Config {
	if c.FusionMode == "" {
		c.FusionMode = FusionWeightedAverage
	}
	if c.BlendWeights.URL+c.BlendWeights.Header+c.BlendWeights.NLP+c.BlendWeights.Attachment <= 0 {
		c.BlendWeights = DefaultWeights()
	}
	// Clamp each channel to [0,1] (NaN→0) BEFORE the all-non-positive guard so a
	// single bad value (e.g. a negative) cannot drag the sum ≤ 0 and silently reset
	// every other channel to full trust.
	c.Reliabilities.URL = clampUnit(c.Reliabilities.URL)
	c.Reliabilities.Header = clampUnit(c.Reliabilities.Header)
	c.Reliabilities.NLP = clampUnit(c.Reliabilities.NLP)
	c.Reliabilities.Attachment = clampUnit(c.Reliabilities.Attachment)
	if c.Reliabilities.URL+c.Reliabilities.Header+c.Reliabilities.NLP+c.Reliabilities.Attachment <= 0 {
		c.Reliabilities = DefaultReliabilities()
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

// buildBlenders constructs both fusion methods once and returns (active, other):
// active is the Blender named by cfg.FusionMode (unknown values fall back to the
// weighted average so a misconfiguration can never leave the engine without a
// blender), and other is the opposite method used for shadow comparison. Building
// both here removes the duplicated, mutually-inverted selector logic.
func buildBlenders(cfg Config) (active, other Blender) {
	wa := NewWeightedAverageBlender(cfg.BlendWeights)
	switch cfg.FusionMode {
	case FusionCalibratedOR:
		// Shadow against the current default (weighted_average) to measure the
		// verdict-band shift before/while ramping the calibrated fusion.
		return NewCalibratedORBlender(), wa
	case FusionNoisyOR:
		return NewReliabilityNoisyORBlender(cfg.Reliabilities), wa
	default:
		return wa, NewReliabilityNoisyORBlender(cfg.Reliabilities)
	}
}

// Publisher is the producer for emails.verdict (subset of
// kafkaproducer.Producer). retries is the number of *extra* attempts after
// the first ProduceSync (same contract as shared/kafka/producer.Producer.Publish).
type Publisher interface {
	Publish(ctx context.Context, key, value []byte, retries int) error
}

// decisionWriter abstracts persistence for testing and wraps *persist.Writer.
type decisionWriter interface {
	Write(ctx context.Context, in persist.Input) (persist.Output, error)
	GetCampaignHistory(ctx context.Context, orgID int64, fingerprint string) (*persist.CampaignHistory, error)
}

type ruleGetter interface {
	Get(ctx context.Context, orgID int64) ([]rules.CachedRule, error)
}

type simhashComputer interface {
	Compute(text string) (uint64, bool)
	Lookup(ctx context.Context, orgID int64, hash uint64) (campaign.Match, bool, error)
	Store(ctx context.Context, orgID, campaignID int64, hash uint64, fingerprint string) error
}

// Engine is the SVC-08 orchestrator. One instance is shared by every
// consumer goroutine; methods are safe for concurrent use.
type Engine struct {
	cfg       Config
	blender   Blender
	shadow    Blender // the non-active fusion, computed for comparison only (never gates)
	rules     ruleGetter
	evaluator *rules.Evaluator
	simhash   simhashComputer
	writer    decisionWriter
	publisher Publisher
	metrics   *metrics.Metrics
	log       zerolog.Logger
	tracer    trace.Tracer
}

// New constructs an Engine.
func New(
	cfg Config,
	rulesCache ruleGetter,
	simhash simhashComputer,
	writer decisionWriter,
	publisher Publisher,
	m *metrics.Metrics,
	log zerolog.Logger,
) *Engine {
	cfg = cfg.Defaults()
	active, other := buildBlenders(cfg)
	eng := &Engine{
		cfg:       cfg,
		blender:   active,
		rules:     rulesCache,
		evaluator: rules.NewEvaluator(log),
		simhash:   simhash,
		writer:    writer,
		publisher: publisher,
		metrics:   m,
		log:       log,
		tracer:    tracing.Tracer("svc-08-decision"),
	}
	// The shadow blender is built only when explicitly enabled, so the e.shadow
	// nil-check in Handle is a real off-switch and default deployments do not pay
	// for a second blend per email.
	if cfg.FusionShadow {
		eng.shadow = other
	}
	return eng
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
		if errors.Is(err, errUnresolvedInternalID) {
			// Poison that escaped svc-07's producer-side drop: the verdict can
			// never be addressed to a DB row. Make it visibly loud (not lumped
			// in with ordinary malformed input). We still commit the offset — a
			// NACK would wedge the partition forever on an unfixable message.
			e.log.Error().Err(err).
				Int("partition", msg.Partition).Int64("offset", msg.Offset).
				Msg("emails.scored has unresolved internal_id (<=0); verdict cannot be addressed — " +
					"dropping (svc-07 should have dropped this at the producer)")
		} else {
			e.log.Error().Err(err).
				Int("partition", msg.Partition).Int64("offset", msg.Offset).
				Msg("malformed emails.scored; skipping")
		}
		return nil // commit offset on malformed/poison input — see brief §8 (3)
	}

	logCtx := e.log.With().
		Str("email_id", scored.Meta.EmailID).
		Int64("org_id", scored.Meta.OrgID).
		Logger()

	span.SetAttributes(
		attribute.String("email_id", scored.Meta.EmailID),
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
		bodyHash uint64
		hasHash  bool
		simMatch campaign.Match
		simHit   bool
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
	if e.rules == nil {
		logCtx.Error().Msg("decision rules cache unavailable; degrading to blend-only verdict")
		return e.publishDegraded(
			ctx, scored, components, blendOut, nudgedScore, fingerprint, history,
			simMatch, simHit, hasHash, bodyHash, time.Since(startedAt),
		)
	}
	rs, err := e.rules.Get(ctx, scored.Meta.OrgID)
	if err != nil {
		logCtx.Error().Err(err).Msg("decision rules cache load failed; degrading to blend-only verdict")
		return e.publishDegraded(
			ctx, scored, components, blendOut, nudgedScore, fingerprint, history,
			simMatch, simHit, hasHash, bodyHash, time.Since(startedAt),
		)
	}

	// preRuleLabel stays the PURE LabelFor band (no attachment reconcile):
	// it is the pre-rule snapshot input that rule conditions match on, so
	// reconciling it here could change which rules fire — a scoring
	// feedback loop. The malware-vs-phishing reconcile is applied only to
	// the final verdict label below.
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
	// Label is reconciled; confidence stays on the score's natural band. The
	// shared seam keeps this path and the degraded path in lockstep — see
	// verdictLabelAndConfidence for the confidence-trap invariant.
	label, confidence := verdictLabelAndConfidence(finalScore, components, scored.PartialAnalysis, source)

	// Shadow: record when the non-active fusion method would emit a different final
	// verdict label. Runs the full pipeline (rules re-evaluated against the shadow's
	// own pre-rule band) so the metric faithfully reflects a switch.
	e.recordFusionShadow(rs, scored, components, campaignHistory, source, label, logCtx)

	procElapsed := time.Since(startedAt)

	wireElapsed := procElapsed // snapshot for VerdictWireBuilder closure
	mv := e.modelVersionFor(scored, source)

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
		ModelVersion:  mv,

		Fired:            fired,
		AnalysisMetadata: marshalAnalysisMetadata(e.cfg.FusionMode, blendOut, nudgedScore, nudgeAlpha, ruleAdjustment, simHit, simMatch),
		VerdictWireBuilder: func(wx persist.VerdictWireContext) ([]byte, error) {
			o := persist.Output{
				CampaignID: wx.CampaignID,
				IsNew:      wx.IsNew,
				EmailCount: wx.EmailCount,
				VerdictID:  wx.VerdictID,
			}
			v := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
				mv, fired, o, fingerprint, wireElapsed)
			return json.Marshal(v)
		},
	})
	if e.metrics != nil {
		e.metrics.DBWriteDuration.Observe(time.Since(dbStart).Seconds())
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "decision tx failed")
		e.bumpStatus("error")
		logCtx.Error().Err(err).Msg("decision tx failed; offset will NOT be committed")
		return fmt.Errorf("decision persist write: %w", err)
	}

	if !out.DedupeSkip && e.metrics != nil {
		if out.IsNew {
			e.metrics.CampaignTotal.WithLabelValues("new").Inc()
		} else {
			e.metrics.CampaignTotal.WithLabelValues("existing").Inc()
		}
	}

	// 6. Best-effort SimHash store — skip on Kafka redelivery: index was
	// populated on the first successful processing path.
	if hasHash && !out.DedupeSkip {
		if err := e.simhash.Store(ctx, scored.Meta.OrgID, out.CampaignID, bodyHash, fingerprint); err != nil {
			logCtx.Debug().Err(err).Int64("campaign_id", out.CampaignID).Msg("simhash store failed; index entry skipped")
		}
	}

	// 7. Publish emails.verdict (prefer kafka_verdict_wire from DB when present).
	body, err := verdictKafkaBody(out, func() ([]byte, error) {
		v := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
			mv, fired, out, fingerprint, procElapsed)
		return json.Marshal(v)
	})
	if err != nil {
		e.bumpStatus("error")
		span.RecordError(err)
		span.SetStatus(codes.Error, "marshal verdict failed")
		return fmt.Errorf("marshal emails.verdict: %w", err)
	}

	if err := e.publisher.Publish(
		ctx,
		encodeKey(scored.Meta.EmailID),
		body,
		e.cfg.PublishRetryAttempts,
	); err != nil {
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
	if out.DedupeSkip {
		logCtx.Info().Msg("emails.scored replay; verdict idempotent in DB, republished emails.verdict to Kafka")
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
	// Same shared seam as the main path: reconciled label, natural-band
	// confidence. See verdictLabelAndConfidence.
	source := VerdictSourceRule
	label, confidence := verdictLabelAndConfidence(finalScore, components, scored.PartialAnalysis, source)
	mvdeg := e.modelVersionFor(scored, source)

	// Shadow: also measure disagreement on the degraded path (rs nil → no rule
	// adjustment, mirroring this path's blend-only verdict) so the calibration
	// sample is not silently biased toward healthy traffic.
	var campaignHistory *campaign.History
	if history != nil {
		campaignHistory = &campaign.History{
			CampaignID: history.CampaignID,
			RiskScore:  history.RiskScore,
			EmailCount: history.EmailCount,
		}
	}
	e.recordFusionShadow(nil, scored, components, campaignHistory, source, label, e.log)

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
		ModelVersion:  mvdeg,

		Fired: nil,
		AnalysisMetadata: marshalAnalysisMetadata(
			e.cfg.FusionMode, blendOut, nudgedScore, 0, 0, simHit, simMatch,
		),
		VerdictWireBuilder: func(wx persist.VerdictWireContext) ([]byte, error) {
			o := persist.Output{
				CampaignID: wx.CampaignID,
				IsNew:      wx.IsNew,
				EmailCount: wx.EmailCount,
				VerdictID:  wx.VerdictID,
			}
			v := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
				mvdeg, nil, o, fingerprint, elapsed)
			return json.Marshal(v)
		},
	})
	if err != nil {
		e.bumpStatus("error")
		return fmt.Errorf("decision persist write (degraded): %w", err)
	}

	if !out.DedupeSkip {
		if hasHash {
			_ = e.simhash.Store(ctx, scored.Meta.OrgID, out.CampaignID, bodyHash, fingerprint)
		}
		if e.metrics != nil {
			if out.IsNew {
				e.metrics.CampaignTotal.WithLabelValues("new").Inc()
			} else {
				e.metrics.CampaignTotal.WithLabelValues("existing").Inc()
			}
		}
	}

	body, err := verdictKafkaBody(out, func() ([]byte, error) {
		v := buildVerdict(scored, finalScore, components, blendOut, label, confidence, source,
			mvdeg, nil, out, fingerprint, elapsed)
		return json.Marshal(v)
	})
	if err != nil {
		return err
	}
	if err := e.publisher.Publish(
		ctx,
		encodeKey(scored.Meta.EmailID),
		body,
		e.cfg.PublishRetryAttempts,
	); err != nil {
		e.bumpStatus("error")
		return fmt.Errorf("publish emails.verdict (degraded): %w", err)
	}
	e.bumpStatus("ok")
	if e.metrics != nil {
		e.metrics.RiskScore.Observe(float64(finalScore))
		e.metrics.VerdictTotal.WithLabelValues(string(label)).Inc()
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

func verdictKafkaBody(out persist.Output, fresh func() ([]byte, error)) ([]byte, error) {
	if len(out.KafkaVerdictWire) > 0 {
		return slices.Clone(out.KafkaVerdictWire), nil
	}
	return fresh()
}

// errUnresolvedInternalID flags an emails.scored whose internal_id is <= 0.
// svc-07 must drop these at the producer; one reaching here is a silent
// data-loss escape (the verdict can never be addressed to a DB row), so Handle
// logs it at Error level distinctly from ordinary malformed input.
var errUnresolvedInternalID = errors.New("emails.scored: internal_id must be > 0")

func decodeScored(b []byte) (contracts.EmailsScored, error) {
	var out contracts.EmailsScored
	if len(b) == 0 {
		return out, errors.New("empty payload")
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("unmarshal emails.scored: %w", err)
	}
	if out.Meta.EmailID == "" {
		return out, errors.New("emails.scored: meta.email_id is required")
	}
	if out.Meta.OrgID <= 0 {
		return out, fmt.Errorf("emails.scored: meta.org_id must be > 0, got %d", out.Meta.OrgID)
	}
	if out.InternalID <= 0 {
		// Poison: svc-07 should have dropped this at the producer (internal_id is
		// the verdict-row key; there is NO email_id fallback). If one slipped
		// through we commit the offset (a NACK would wedge the partition forever)
		// but surface it loudly via errUnresolvedInternalID — see Handle.
		return out, fmt.Errorf("%w: got %d", errUnresolvedInternalID, out.InternalID)
	}
	if out.FetchedAt.IsZero() {
		return out, errors.New("emails.scored: fetched_at is required (emails partition key)")
	}
	if !out.Meta.FetchedAt.IsZero() && !out.Meta.FetchedAt.Equal(out.FetchedAt) {
		return out, fmt.Errorf("emails.scored: meta.fetched_at and top-level fetched_at disagree (%v vs %v)",
			out.Meta.FetchedAt.UTC(), out.FetchedAt.UTC())
	}
	out.Meta.FetchedAt = out.FetchedAt.UTC()
	return out, nil
}

func encodeKey(emailID string) []byte {
	return []byte(emailID)
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

// recordFusionShadow computes the verdict label the non-active fusion method would
// emit and increments decision_fusion_shadow_disagree_total when it differs from the
// active label. No-op unless the shadow blender is enabled (cfg.FusionShadow). It
// never affects the verdict. rs may be nil (degraded path: no rule adjustment),
// mirroring the active path.
func (e *Engine) recordFusionShadow(
	rs []rules.CachedRule,
	scored contracts.EmailsScored,
	components Components,
	campaignHistory *campaign.History,
	source string,
	activeLabel Label,
	logCtx zerolog.Logger,
) {
	if e.shadow == nil || e.metrics == nil || !components.HasAny() {
		return
	}
	shadowLabel := e.shadowVerdictLabel(rs, scored, components, campaignHistory)
	if shadowLabel == activeLabel {
		return
	}
	e.metrics.FusionShadowDisagree.WithLabelValues(string(activeLabel), string(shadowLabel)).Inc()
	logCtx.Debug().
		Str("active_label", string(activeLabel)).
		Str("shadow_label", string(shadowLabel)).
		Msg("fusion shadow disagreement")
}

// shadowVerdictLabel runs the non-active fusion method through the same pipeline the
// active verdict takes — blend → nudge → rule evaluation → reconcile — and returns
// its final reconciled label. Rules are re-evaluated against the shadow score's own
// pre-rule band (not the active path's adjustment) so a switch is measured
// faithfully. rs nil → no rule adjustment (degraded path). Confidence is not
// computed; only the band is needed for the comparison.
func (e *Engine) shadowVerdictLabel(
	rs []rules.CachedRule,
	scored contracts.EmailsScored,
	components Components,
	campaignHistory *campaign.History,
) Label {
	shadowScore := e.shadow.Blend(components).Score
	shadowNudged, _ := campaign.Nudge(shadowScore, campaignHistory, e.cfg.Shrinkage)
	adjustment := 0
	if rs != nil {
		snap := BuildSnapshot(SnapshotInputs{
			Scored:        scored,
			Components:    components,
			BlendedScore:  shadowScore,
			NudgedScore:   shadowNudged,
			PreRuleLabel:  LabelFor(Round(shadowNudged)),
			CampaignState: campaignHistory,
		})
		_, adjustment = e.evaluator.Evaluate(rs, snap)
	}
	shadowFinal := ClampInt(Round(shadowNudged)+adjustment, 0, 100)
	return ReconcileLabel(shadowFinal, components)
}

// marshalAnalysisMetadata builds the JSONB blob written to
// emails.analysis_metadata for explainability. Per design brief §3.4,
// component contributions are preserved here regardless of blending
// method; the blob also records the campaign-nudge details.
//
// blend.method names the fusion method so consumers can interpret the
// contributions correctly: under "weighted_average" the contributions are
// per-component shares that SUM to blend.score, while under "noisy_or" they are
// per-channel probabilities in [0,1] (reliability × score/100) that do NOT sum to
// the score. weight_sum is Σ weight (weighted_average) or Σ reliability (noisy_or)
// over present components.
func marshalAnalysisMetadata(
	method string,
	blendOut BlendResult,
	nudgedScore float64,
	nudgeAlpha float64,
	ruleAdjustment int,
	simHit bool,
	simMatch campaign.Match,
) []byte {
	meta := map[string]any{
		"blend": map[string]any{
			"method":        method,
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
			"matched":          true,
			"matched_campaign": simMatch.CampaignID,
			"hamming_distance": simMatch.Distance,
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
	meta := contracts.NewMeta(scored.Meta.EmailID, scored.Meta.OrgID)
	meta.FetchedAt = scored.FetchedAt.UTC()
	campID := out.CampaignID
	verdict := contracts.EmailsVerdict{
		Meta:                  meta,
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
