// svc-06 nlp-pipeline is the Kafka-side binary for SVC-06 NLP Analysis.
// Distinct from cmd/nlp (the standalone HTTP /predict demo) — this
// binary consumes analysis.text from Kafka, calls the real DistilBERT
// FastAPI service over HTTP, and publishes the model's content_risk_score
// to scores.nlp.
//
// CYBERSIREN_ML__NLP_SERVICE_URL must point at a running FastAPI service
// (default http://localhost:8001). The smoke target ensures one is up.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-06-nlp/internal/nlp"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName    = "svc-06-nlp"
	predictTimeout = 10 * time.Second
)

// versionHeuristic is the version string recorded for every facet in the
// scores.nlp model_versions envelope so downstream consumers can reason about
// score provenance. All four facets (urgency/intent/impersonation/deception)
// are pure keyword/domain heuristics (CONSTRAINT G4: no NER, no retraining) —
// the intent label is a deterministic mapping (mapIntentTo5Label) over the
// Python 11-class intent_labels, it does NOT retrain DistilBERT — so they
// currently share one version. model_versions still carries a field per facet,
// so if one heuristic diverges, give that field its own constant and bump it.
const versionHeuristic = "heuristic-1.0"

// 5-label intent taxonomy (ARCH-SPEC; see contracts.NLPFacets.IntentLabel).
const (
	intentCredentialHarvesting = "credential_harvesting"
	intentMalwareDelivery      = "malware_delivery"
	intentBEC                  = "bec"
	intentScam                 = "scam"
	intentLegitimate           = "legitimate"
)

// intent5Priority orders the 5 spec labels from highest threat priority to
// lowest. When a single email's Python intent_labels map onto more than one
// spec label, the highest-priority one wins (index 0 is highest). legitimate
// is the lowest and only surfaces when nothing else matches.
var intent5Priority = []string{
	intentCredentialHarvesting,
	intentMalwareDelivery,
	intentBEC,
	intentScam,
	intentLegitimate,
}

// intent11To5 maps each Python _INTENT_PATTERNS key (inference.py) onto exactly
// one of the 5 spec labels.
//
//	credential_harvest, account_verification, data_exfiltration -> credential_harvesting
//	malware_delivery                                            -> malware_delivery
//	social_engineering, urgency_threat, impersonation          -> bec
//	payment_fraud, prize_scam                                  -> scam
//	marketing_spam, benign_notification                        -> legitimate
//
// impersonation -> bec: brand-impersonation in this corpus is overwhelmingly a
// pretext for business-email-compromise style requests (the standalone brand
// signal is already carried separately as impersonation_score/impersonated_brand),
// so folding it into bec keeps scam reserved for financial-lure fraud.
var intent11To5 = map[string]string{
	"credential_harvest":   intentCredentialHarvesting,
	"account_verification": intentCredentialHarvesting,
	"data_exfiltration":    intentCredentialHarvesting,
	"malware_delivery":     intentMalwareDelivery,
	"social_engineering":   intentBEC,
	"urgency_threat":       intentBEC,
	"impersonation":        intentBEC,
	"payment_fraud":        intentScam,
	"prize_scam":           intentScam,
	"marketing_spam":       intentLegitimate,
	"benign_notification":  intentLegitimate,
}

// mapIntentTo5Label collapses the Python 11-class intent_labels into exactly
// one of the 5 spec labels (credential_harvesting | malware_delivery | bec |
// scam | legitimate) plus a deterministic confidence.
//
// Resolution:
//   - classification=="legitimate" or no intent labels => ("legitimate", 1.0).
//   - Otherwise map every recognised intent to its 5-label bucket and pick the
//     highest-priority bucket (intent5Priority). Unknown Python labels are
//     ignored.
//   - If nothing maps (only unknown labels) => ("legitimate", 0.5).
//
// Confidence reflects how cleanly the winning label was chosen: it is the
// fraction of *recognised* intents that agree with the winning bucket. A single
// matching intent yields 1.0; competing buckets dilute it. This is fully
// deterministic and bounded to (0, 1].
func mapIntentTo5Label(intentLabels []string, classification string) (string, float64) {
	if classification == intentLegitimate || len(intentLabels) == 0 {
		return intentLegitimate, 1.0
	}

	bucketCounts := make(map[string]int)
	recognised := 0
	for _, lbl := range intentLabels {
		bucket, ok := intent11To5[lbl]
		if !ok {
			continue
		}
		recognised++
		bucketCounts[bucket]++
	}

	if recognised == 0 {
		// Only unknown labels: classification was not "legitimate" but we have
		// no usable signal, so fall back to legitimate with low confidence.
		return intentLegitimate, 0.5
	}

	// Highest-priority bucket that actually matched wins.
	winner := intentLegitimate
	for _, candidate := range intent5Priority {
		if bucketCounts[candidate] > 0 {
			winner = candidate
			break
		}
	}

	confidence := float64(bucketCounts[winner]) / float64(recognised)
	return winner, confidence
}

var nlpClient *nlp.Client

// predictor is the narrow slice of *nlp.Client that the core handler needs.
// Extracting it lets tests inject a fake that returns context.DeadlineExceeded
// (or any failure) without standing up the real FastAPI service.
type predictor interface {
	Predict(ctx context.Context, req nlp.PredictRequest) (*nlp.PredictResponse, int, error)
}

// publishFunc abstracts the scores.nlp emit so tests can capture the published
// bytes instead of talking to a real Kafka producer. deps.Producers holds the
// concrete *kafkaproducer.Producer, so handle() closes over it here and the
// extracted core logic only depends on this function.
type publishFunc func(ctx context.Context, key, value []byte) error

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: []string{contracts.TopicScoresNLP},
		ConsumerTopics: []string{contracts.TopicAnalysisText},
		GroupID:        contracts.GroupNLPAnalysis,
		OnReady: func(ctx context.Context, deps svckit.Deps) error {
			base := deps.Cfg.ML.NLPServiceURL
			if base == "" {
				return fmt.Errorf("ml.nlp_service_url is empty (set CYBERSIREN_ML__NLP_SERVICE_URL)")
			}
			c := nlp.NewClient(base, deps.Registry, deps.Log)
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if ok, err := c.Health(pingCtx); err != nil || !ok {
				return fmt.Errorf(
					"NLP /healthz at %s failed: %w "+
						"(start the FastAPI service via `make smoke` "+
						"or `docker compose --profile nlp-inference up`)",
					base, err)
			}
			nlpClient = c
			deps.Log.Info().Str("nlp_service_url", base).Msg("NLP client ready")
			return nil
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var input contracts.AnalysisText
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.text: %w", err)
	}

	// Resolve the scores.nlp producer up front: a missing producer is an infra
	// misconfiguration (not a model timeout) and must surface as an error.
	prod, ok := deps.Producers[contracts.TopicScoresNLP]
	if !ok {
		return fmt.Errorf("svc-06: producer for %s not configured", contracts.TopicScoresNLP)
	}
	publish := func(ctx context.Context, key, value []byte) error {
		return prod.Publish(ctx, key, value, 1) // +1 kafka retry
	}

	return process(ctx, input, nlpClient, publish)
}

// process is the testable core of the handler: it predicts a content risk
// score (falling back to a neutral 50 on any predict failure/timeout) and
// publishes the scores.nlp envelope. It depends only on the predictor and
// publishFunc abstractions so tests can drive it without a live FastAPI
// service or real Kafka.
func process(ctx context.Context, input contracts.AnalysisText, pred predictor, publish publishFunc) error {
	log := zerolog.Ctx(ctx).With().Str("email_id", input.Meta.EmailID).Logger()

	ft := input.Meta.FetchedAt
	if ft.IsZero() {
		ft = time.Now().UTC()
	}
	meta := contracts.NewMetaWithFetched(input.Meta.EmailID, input.Meta.OrgID, ft)

	predCtx, cancel := context.WithTimeout(ctx, predictTimeout)
	resp, status, err := pred.Predict(predCtx, nlp.PredictRequest{
		Subject:      input.Subject,
		BodyPlain:    input.Body,
		SenderName:   input.SenderName,
		SenderDomain: input.SenderDomain,
	})
	cancel()

	// Per-branch values. The defaults describe the fallback (no model ran)
	// state; the success branch overwrites them. Both paths then build ONE
	// envelope below so the emitted scores.nlp shape is identical whether the
	// model answered or timed out — every consumer (svc-07 decoder, svc-08
	// fingerprint, the console) reads the same keys on either path.
	var (
		score          float64 = 50
		classification         = "unknown"
		intentLabels           = []string{} // empty (not nil) for shape stability
		phishProb      float64
		confidence     float64
		obfuscation    bool
		facets         = contracts.NLPFacets{IntentLabel: intentLegitimate}
		fallbackInfo   map[string]interface{}
	)

	if err != nil {
		// Spec §6 fallback: a slow/unreachable/non-2xx model must NOT NACK the
		// message and stall the partition (head-of-line blocking). Emit the
		// neutral score of 50 and commit the offset.
		// Distinguish a deadline/timeout from a service failure (non-2xx or
		// unreachable) so downstream consumers don't mis-attribute every
		// fallback as a timeout. status==0 is the unreachable/deadline path.
		fallbackReason := "nlp_predict_failed"
		if errors.Is(err, context.DeadlineExceeded) {
			fallbackReason = "nlp_predict_timeout"
		}
		log.Warn().
			Err(err).
			Int("status", status).
			Str("fallback_reason", fallbackReason).
			Msg("nlp predict failed/timed out; emitting fallback content_risk_score=50")
		fallbackInfo = map[string]interface{}{
			"fallback":        true,
			"fallback_reason": fallbackReason,
			"fallback_error":  err.Error(),
		}
	} else {
		// Heuristic 5-label intent collapsed from the Python 11-class
		// intent_labels. The full intent_labels list is still emitted below for
		// SVC-08's fingerprint; intent_label/intent_confidence add the single
		// spec-taxonomy label (also surfaced inside facets).
		intentLabel, intentConf := mapIntentTo5Label(resp.IntentLabels, resp.Classification)
		score = float64(resp.ContentRiskScore)
		classification = resp.Classification
		intentLabels = resp.IntentLabels
		phishProb = resp.PhishingProbability
		confidence = resp.Confidence
		obfuscation = resp.ObfuscationDetected
		facets = contracts.NLPFacets{
			UrgencyScore:       resp.UrgencyScore,
			IntentLabel:        intentLabel,
			IntentConfidence:   intentConf,
			ImpersonationScore: resp.ImpersonationScore,
			ImpersonatedBrand:  resp.ImpersonatedBrand,
			DeceptionScore:     resp.DeceptionScore,
		}
	}

	// Single envelope shared by both paths. The topic stays a
	// contracts.ScoreEnvelope because svc-07's decoder decodes scores.nlp as
	// ScoreEnvelope and svc-08's fingerprint reads intent_labels/subject/
	// plain_text out of this Details map. NLPFacets / NLPModelVersions
	// JSON-marshal to the spec facets{} / model_versions{} shapes.
	details := map[string]interface{}{
		"classification":       classification,
		"phishing_probability": phishProb,
		"confidence":           confidence,
		"intent_labels":        intentLabels,
		"urgency_score":        facets.UrgencyScore,
		"obfuscation_detected": obfuscation,
		"facets":               facets,
		"model_versions": contracts.NLPModelVersions{
			Urgency:       versionHeuristic,
			Intent:        versionHeuristic,
			Impersonation: versionHeuristic,
			Deception:     versionHeuristic,
		},
		"intent_label":      facets.IntentLabel,
		"intent_confidence": facets.IntentConfidence,
		// subject + plain_text carry the content dimension SVC-08's campaign
		// fingerprint and SimHash near-dedup read from component_details.nlp.
		// details (ARCH-SPEC §8.1). Without them the fingerprint's subject
		// dimension collapses to SHA256("") and SimHash never runs. Body is the
		// HTML-stripped clean plain text (spec field: plain_text).
		"subject":    input.Subject,
		"plain_text": input.Body,
	}
	// Fallback-only provenance keys, layered on the otherwise-identical shape.
	for k, v := range fallbackInfo {
		details[k] = v
	}
	out := contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope producer.
		Meta:      meta,
		Component: contracts.ComponentNLP,
		Score:     score,
		Details:   details,
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal scores.nlp: %w", err)
	}
	if err := publish(ctx, []byte(input.Meta.EmailID), body); err != nil {
		return fmt.Errorf("publish scores.nlp: %w", err)
	}

	if resp != nil {
		log.Info().
			Int("content_risk_score", resp.ContentRiskScore).
			Str("classification", resp.Classification).
			Float64("phishing_probability", resp.PhishingProbability).
			Msg("scored email text")
	}
	return nil
}
