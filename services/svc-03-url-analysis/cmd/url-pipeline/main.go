// svc-03 url-pipeline is the Kafka-side binary for SVC-03 URL Analysis.
// It is distinct from cmd/url-analysis (the standalone HTTP demo) but uses
// the SAME internal/url Go module. Per URL it runs:
//
//  1. shared/normalization.NormalizeURL → canonical form
//  2. urlpkg.URLModel.PredictWithRoute  → XGBoost score + routing flag
//  3. urlpkg.TIChecker.Check            → Valkey-cached domain blocklist
//  4. classifyLabel(score, ti, routed)  → final label per the demo's logic
//
// scores.url carries the maximum risk score across all URLs in the email,
// plus the strongest TI hit and the per-URL detail for downstream debug.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/postgres/repository"
	"github.com/saif/cybersiren/shared/svckit"
	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

const (
	serviceName    = "svc-03-url-analysis"
	predictTimeout = 5 * time.Second
)

var (
	urlModel  *url.URLModel
	tiChecker *url.TIChecker
)

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
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
				return fmt.Errorf(
					"load URL model from %s: %w "+
						"(install xgboost/joblib/scikit-learn locally or set CYBERSIREN_ML__URL_MODEL_PATH)",
					scriptPath, err)
			}
			urlModel = m
			log.Info().Str("script", scriptPath).Int("pool", poolSize).Msg("URL model ready")

			// TI checker: Valkey-cached domain blocklist backed by Postgres
			// ti_indicators. Mirrors the standalone /scan demo wiring.
			tiRepo := repository.NewTIRepository(deps.Pool, deps.Log, deps.Registry)
			tiCache := sharedvalkey.NewTICache(deps.Valkey, tiRepo, deps.Log, deps.Registry, 0)
			if err := tiCache.RefreshDomainCache(ctx); err != nil {
				log.Warn().Err(err).Msg("initial TI domain cache refresh failed (continuing)")
			}
			tiChecker = url.NewTIChecker(tiCache, log)
			log.Info().Msg("TI checker ready")
			return nil
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// urlScan is the per-URL outcome aggregated into scores.url Details.
type urlScan struct {
	URL          string  `json:"url"`
	Normalized   string  `json:"normalized,omitempty"`
	Score        int     `json:"score"`
	Probability  float64 `json:"probability"`
	Routed       bool    `json:"routed_to_enrichment"`
	RouteReason  string  `json:"route_reason,omitempty"`
	TIMatch      bool    `json:"ti_match"`
	TIThreatType string  `json:"ti_threat_type,omitempty"`
	TIRiskScore  int     `json:"ti_risk_score"`
	Label        string  `json:"label"`
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var input contracts.AnalysisURLs
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.urls: %w", err)
	}

	log := zerolog.Ctx(ctx).With().Int64("email_id", input.Meta.EmailID).Logger()

	scans := make([]urlScan, 0, len(input.URLs))
	maxScore := 0
	maxProb := 0.0
	maxTIRisk := 0
	worstLabel := "legitimate"

	for _, raw := range input.URLs {
		s := scanOne(ctx, raw, log)
		scans = append(scans, s)
		if s.Score > maxScore {
			maxScore = s.Score
			maxProb = s.Probability
		}
		if s.TIRiskScore > maxTIRisk {
			maxTIRisk = s.TIRiskScore
		}
		worstLabel = worseLabel(worstLabel, s.Label)
	}

	out := contracts.ScoreEnvelope{
		Meta:      contracts.NewMeta(input.Meta.EmailID, input.Meta.OrgID),
		Component: contracts.ComponentURL,
		Score:     float64(maxScore),
		Details: map[string]interface{}{
			"urls_total":               len(input.URLs),
			"max_phishing_probability": maxProb,
			"max_ti_risk_score":        maxTIRisk,
			"worst_label":              worstLabel,
			"per_url":                  scans,
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

	log.Info().
		Int("urls", len(input.URLs)).
		Int("max_score", maxScore).
		Int("max_ti_risk", maxTIRisk).
		Str("worst_label", worstLabel).
		Msg("scored URLs")
	return nil
}

// scanOne mirrors the standalone /scan handler: normalise, run ML + TI in
// parallel, classify into a label.
func scanOne(ctx context.Context, raw string, log zerolog.Logger) urlScan {
	out := urlScan{URL: raw, Label: "legitimate"}

	normalized, err := normalization.NormalizeURL(raw)
	if err != nil {
		log.Warn().Err(err).Str("url", raw).Msg("URL normalisation failed; skipping")
		return out
	}
	out.Normalized = normalized

	predCtx, cancel := context.WithTimeout(ctx, predictTimeout)
	defer cancel()

	var (
		mlScore int
		mlProb  float64
		routed  bool
		reason  string
		tiRes   url.TIResult
		wg      sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		mlScore, mlProb, routed, reason, _ = urlModel.PredictWithRoute(predCtx, normalized)
	}()
	go func() {
		defer wg.Done()
		tiRes, _ = tiChecker.Check(predCtx, normalized)
	}()
	wg.Wait()

	out.Score = mlScore
	out.Probability = mlProb
	out.Routed = routed
	out.RouteReason = reason
	out.TIMatch = tiRes.Matched
	out.TIThreatType = tiRes.ThreatType
	out.TIRiskScore = tiRes.RiskScore
	out.Label = classifyLabel(mlScore, tiRes, routed)
	return out
}

// classifyLabel mirrors the rule set in cmd/url-analysis/main.go.
func classifyLabel(mlScore int, ti url.TIResult, routed bool) string {
	if ti.Matched && ti.RiskScore >= 80 {
		return "phishing"
	}
	if routed {
		return "suspicious"
	}
	switch {
	case mlScore >= 70:
		return "phishing"
	case mlScore >= 40:
		return "suspicious"
	default:
		return "legitimate"
	}
}

// worseLabel returns the more severe of two label values.
func worseLabel(a, b string) string {
	rank := map[string]int{"legitimate": 0, "suspicious": 1, "phishing": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
