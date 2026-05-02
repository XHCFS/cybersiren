// svc-03 url-pipeline is the Kafka-side binary for SVC-03 URL Analysis.
// It is distinct from cmd/url-analysis (the standalone HTTP demo) — this
// binary consumes analysis.urls from Kafka, runs every URL through the
// real XGBoost model (Python subprocess pool from internal/url), and
// publishes the maximum risk score to scores.url.
//
// If the model fails to load (xgboost / joblib missing locally, model
// file not present), the binary fails fast at startup so smoke surfaces
// the misconfiguration. There is no random-fallback path.
package main

import (
	"strconv"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName = "svc-03-url-analysis"
	predictTimeout = 5 * time.Second
)

var urlModel *url.URLModel

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: []string{contracts.TopicScoresURL},
		ConsumerTopics: []string{contracts.TopicAnalysisURLs},
		GroupID:        contracts.GroupURLAnalysis,
		OnReady: func(ctx context.Context, deps svckit.Deps) error {
			scriptPath := deps.Cfg.ML.URLModelPath
			poolSize := deps.Cfg.ML.URLModelPoolSize
			if poolSize <= 0 {
				poolSize = 2
			}
			log := deps.Log
			m, err := url.NewURLModel(scriptPath, poolSize, func(msg string, e error) {
				log.Error().Err(e).Msg(msg)
			})
			if err != nil {
				return fmt.Errorf("load URL model from %s: %w (install xgboost/joblib/scikit-learn locally or set CYBERSIREN_ML__URL_MODEL_PATH)", scriptPath, err)
			}
			urlModel = m
			log.Info().Str("script", scriptPath).Int("pool", poolSize).Msg("URL model ready")
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
	var input contracts.AnalysisURLs
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.urls: %w", err)
	}

	log := zerolog.Ctx(ctx).With().Int64("email_id", input.Meta.EmailID).Logger()

	maxScore := 0
	maxProb := 0.0
	scoredURLs := 0
	perURL := make([]map[string]any, 0, len(input.URLs))

	for _, u := range input.URLs {
		predCtx, cancel := context.WithTimeout(ctx, predictTimeout)
		score, prob, err := urlModel.Predict(predCtx, u)
		cancel()
		if err != nil {
			log.Warn().Err(err).Str("url", u).Msg("URL inference failed; skipping")
			continue
		}
		scoredURLs++
		if score > maxScore {
			maxScore = score
			maxProb = prob
		}
		perURL = append(perURL, map[string]any{
			"url":        u,
			"score":      score,
			"probability": prob,
		})
	}

	out := contracts.ScoreEnvelope{
		Meta:      contracts.NewMeta(input.Meta.EmailID, input.Meta.OrgID),
		Component: contracts.ComponentURL,
		Score:     float64(maxScore),
		Details: map[string]interface{}{
			"urls_scored":          scoredURLs,
			"urls_total":           len(input.URLs),
			"max_phishing_probability": maxProb,
			"per_url":              perURL,
		},
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal scores.url: %w", err)
	}
	prod, ok := deps.Producers[contracts.TopicScoresURL]
	if !ok {
		return fmt.Errorf("svc-03: producer for %s not configured", contracts.TopicScoresURL)
	}
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(input.Meta.EmailID, 10)), body, 1); err != nil {
		return fmt.Errorf("publish scores.url: %w", err)
	}

	log.Info().Int("max_score", maxScore).Int("urls_scored", scoredURLs).Msg("scored URLs")
	return nil
}
