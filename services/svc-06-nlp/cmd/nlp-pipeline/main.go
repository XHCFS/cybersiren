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
		Subject:   input.Subject,
		BodyPlain: input.Body,
	})
	cancel()

	var out contracts.ScoreEnvelope //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope producer.
	if err != nil {
		// Spec §6 fallback: a slow/unreachable/non-2xx model must NOT NACK the
		// message and stall the partition (head-of-line blocking). Emit the
		// neutral score of 50 and commit the offset. subject + plain_text are
		// still carried so SVC-08's fingerprint/SimHash keep working.
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
		out = contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope producer.
			Meta:      meta,
			Component: contracts.ComponentNLP,
			Score:     50,
			Details: map[string]interface{}{
				"classification":  "unknown",
				"fallback":        true,
				"fallback_reason": fallbackReason,
				"fallback_error":  err.Error(),
				// subject + plain_text carry the content dimension SVC-08's
				// campaign fingerprint and SimHash near-dedup read from
				// component_details.nlp.details (ARCH-SPEC §8.1).
				"subject":    input.Subject,
				"plain_text": input.Body,
			},
		}
	} else {
		out = contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope producer.
			Meta:      meta,
			Component: contracts.ComponentNLP,
			Score:     float64(resp.ContentRiskScore),
			Details: map[string]interface{}{
				"classification":       resp.Classification,
				"phishing_probability": resp.PhishingProbability,
				"confidence":           resp.Confidence,
				"intent_labels":        resp.IntentLabels,
				"urgency_score":        resp.UrgencyScore,
				"obfuscation_detected": resp.ObfuscationDetected,
				// subject + plain_text carry the content dimension SVC-08's
				// campaign fingerprint and SimHash near-dedup read from
				// component_details.nlp.details (ARCH-SPEC §8.1). Without them the
				// fingerprint's subject dimension collapses to SHA256("") and
				// SimHash never runs. Body is the HTML-stripped clean plain text
				// (spec field: plain_text).
				"subject":    input.Subject,
				"plain_text": input.Body,
			},
		}
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
