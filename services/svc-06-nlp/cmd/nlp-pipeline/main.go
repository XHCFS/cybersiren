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
	"strconv"
	"context"
	"encoding/json"
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
				return fmt.Errorf("NLP /healthz at %s failed: %w (start the FastAPI service via `make smoke` or `docker compose --profile nlp-inference up`)", base, err)
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

	log := zerolog.Ctx(ctx).With().Int64("email_id", input.Meta.EmailID).Logger()

	predCtx, cancel := context.WithTimeout(ctx, predictTimeout)
	resp, status, err := nlpClient.Predict(predCtx, nlp.PredictRequest{
		Subject:   input.Subject,
		BodyPlain: input.Body,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("nlp predict (status=%d): %w", status, err)
	}

	out := contracts.ScoreEnvelope{
		Meta:      contracts.NewMeta(input.Meta.EmailID, input.Meta.OrgID),
		Component: contracts.ComponentNLP,
		Score:     float64(resp.ContentRiskScore),
		Details: map[string]interface{}{
			"classification":       resp.Classification,
			"phishing_probability": resp.PhishingProbability,
			"confidence":           resp.Confidence,
			"intent_labels":        resp.IntentLabels,
			"urgency_score":        resp.UrgencyScore,
			"obfuscation_detected": resp.ObfuscationDetected,
		},
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal scores.nlp: %w", err)
	}
	prod, ok := deps.Producers[contracts.TopicScoresNLP]
	if !ok {
		return fmt.Errorf("svc-06: producer for %s not configured", contracts.TopicScoresNLP)
	}
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(input.Meta.EmailID, 10)), body, 1); err != nil {
		return fmt.Errorf("publish scores.nlp: %w", err)
	}

	log.Info().
		Int("content_risk_score", resp.ContentRiskScore).
		Str("classification", resp.Classification).
		Float64("phishing_probability", resp.PhishingProbability).
		Msg("scored email text")
	return nil
}
