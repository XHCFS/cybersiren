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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/internal/phishing"
	phclient "github.com/saif/cybersiren/internal/phishing/client"
	"github.com/saif/cybersiren/internal/phishing/enricher"
	"github.com/saif/cybersiren/services/svc-03-url-analysis/internal/persist"
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
	// urlScoreTTL is how long a scored URL stays in the url_score cache.
	urlScoreTTL = 6 * time.Hour
	// priorEnrichmentTTL is how recently a URL must have been enriched for the
	// pipeline to reuse the stored enrichment instead of re-fetching it.
	priorEnrichmentTTL = 7 * 24 * time.Hour
	// maxConcurrentURLs caps per-email URL enrichment fan-out (ARCH-SPEC §1 step 3a).
	maxConcurrentURLs = 5
)

var (
	urlModel         *url.URLModel
	tiChecker        *url.TIChecker
	phishingDetector *phishing.Detector
	scanMetrics      *url.ScanMetrics
	dbPool           *pgxpool.Pool
	urlCache         valkeygo.Client
	enrichWriter     *persist.Writer
	pipelineTracer   = otel.Tracer("svc-03-url-pipeline/scan-one")
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

			// Per-service Prometheus collectors covering the L1/TI/L2 stages plus
			// the phishing client's cache + sidecar HTTP path.
			scanMetrics = url.NewScanMetrics(deps.Registry)
			phishingMetrics := phclient.NewMetrics(deps.Registry)

			// Layer-2 ML phishing detector (fail-open: missing GeoIP or unreachable
			// sidecar should not prevent the service from starting). When GeoIPDir
			// loads, the detector enriches in-process and uses /score-features;
			// otherwise it falls back to /score (sidecar-side enrichment).
			det, detErr := phishing.NewDetector(phishing.Config{
				SidecarURL: deps.Cfg.Phishing.SidecarURL,
				GeoIPDir:   deps.Cfg.Phishing.GeoIPDir,
				Threshold:  deps.Cfg.Phishing.Threshold,
				Metrics:    phishingMetrics,
				Log:        log,
			})
			if detErr != nil {
				log.Warn().Err(detErr).Msg("phishing ML detector init failed; Layer-2 scoring disabled")
			} else {
				phishingDetector = det
				log.Info().
					Str("sidecar", deps.Cfg.Phishing.SidecarURL).
					Str("geoip_dir", deps.Cfg.Phishing.GeoIPDir).
					Bool("go_enricher", det.UsesGoEnricher()).
					Msg("phishing ML detector ready")
			}

			// Persistence + caching backing stores for pipeline parity.
			dbPool = deps.Pool
			urlCache = deps.Valkey
			enrichWriter = persist.NewWriter(deps.Pool, log)
			log.Info().Msg("url_score cache + enrichment persistence ready")
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
	// GuardHit is set when the domain guard short-circuits scoring.
	// "allowlisted" / "typosquat:<brand>" / "brand-in-subdomain:<brand>".
	GuardHit string `json:"guard_hit,omitempty"`
	// Layer-2 ML fields — populated only on TI-feed misses.
	MLDeployP  float64 `json:"ml_deploy_p,omitempty"`
	MLVerdict  string  `json:"ml_verdict,omitempty"`
	MLCacheHit bool    `json:"ml_cache_hit,omitempty"`
	Label      string  `json:"label"`

	// fresh marks a URL scored this run (not served from the url_score cache);
	// only fresh scans are persisted. Not serialised onto scores.url.
	fresh bool
	// urlP/opP/deployP carry the L2 fusion probabilities through to persistence.
	urlP, opP, deployP float64
	// tiIndicatorID is the matched TI indicator (0 = no match), for the
	// email_url_ti_matches audit row.
	tiIndicatorID int64
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var input contracts.AnalysisURLs
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.urls: %w", err)
	}

	log := zerolog.Ctx(ctx).With().Int64("email_id", input.Meta.EmailID).Logger()

	ft := input.Meta.FetchedAt
	if ft.IsZero() {
		ft = time.Now().UTC()
	}

	// Scan all URLs of the email concurrently, capped at maxConcurrentURLs.
	scans := make([]urlScan, len(input.URLs))
	enrichments := make([]*enricher.EnrichedURL, len(input.URLs))
	sem := make(chan struct{}, maxConcurrentURLs)
	var wg sync.WaitGroup
	for i, raw := range input.URLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			scans[i], enrichments[i] = scanOne(ctx, raw, log)
		}(i, raw)
	}
	wg.Wait()

	maxScore := 0
	maxProb := 0.0
	maxTIRisk := 0
	worstLabel := "legitimate"
	for _, s := range scans {
		if s.Score > maxScore {
			maxScore = s.Score
			maxProb = s.Probability
		}
		if s.TIRiskScore > maxTIRisk {
			maxTIRisk = s.TIRiskScore
		}
		worstLabel = worseLabel(worstLabel, s.Label)
	}

	// Persist enrichment best-effort: scores.url is the SLA-bound output, so a
	// DB failure is logged + metered but does not block the publish below.
	persistEnrichment(ctx, input.Meta.EmailID, ft, scans, enrichments, log)
	out := contracts.ScoreEnvelope{
		Meta:      contracts.NewMetaWithFetched(input.Meta.EmailID, input.Meta.OrgID, ft),
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
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(input.Meta.EmailID, 10)), body, 1); err != nil { // +1 kafka retry
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
// parallel, classify into a label. It returns the per-URL outcome plus the
// in-process enrichment (nil unless a fresh Go-enricher L2 scan ran), which the
// caller persists. A url_score cache hit short-circuits the whole pipeline.
func scanOne(ctx context.Context, raw string, log zerolog.Logger) (urlScan, *enricher.EnrichedURL) {
	start := time.Now()
	defer func() { scanMetrics.ObserveDuration(time.Since(start).Seconds()) }()

	// Raw URL on the span attribute is high-cardinality but invaluable in
	// Jaeger when diagnosing a single bad classification.
	ctx, span := pipelineTracer.Start(ctx, "svc-03.pipeline.scanOne")
	defer span.End()
	span.SetAttributes(attribute.String("scan.url_raw", raw))

	out := urlScan{URL: raw, Label: "legitimate"}

	normalized, err := normalization.NormalizeURL(raw)
	if err != nil {
		scanMetrics.IncStageError("normalize")
		span.RecordError(err)
		log.Warn().Err(err).Str("url", raw).Msg("URL normalisation failed; skipping")
		return out, nil
	}
	out.Normalized = normalized
	span.SetAttributes(attribute.String("scan.url", normalized))

	// url_score cache: a hit short-circuits guard/L1/TI/L2 and persistence.
	cacheKey := urlScoreKey(normalized)
	if cached, ok := cacheGet(ctx, cacheKey); ok {
		scanMetrics.IncCache("hit")
		cached.URL = raw
		cached.fresh = false
		span.SetAttributes(attribute.Bool("scan.cache_hit", true))
		return cached, nil
	}
	scanMetrics.IncCache("miss")
	out.fresh = true

	// Domain guard fast-path. Mirrors the /scan handler: allowlist short-
	// circuits to legitimate (skip L1+TI+L2 entirely); typosquat and
	// brand-in-subdomain short-circuit to phishing. Without this, the
	// Kafka pipeline that processes email-extracted URLs (the production
	// path) would bypass the Cisco-top-10K + brand checks that /scan
	// already enjoys.
	guardCtx, guardSpan := pipelineTracer.Start(ctx, "svc-03.pipeline.guard.CheckDomain")
	apex := url.ApexFromURL(normalized)
	guard := url.CheckDomain(apex)
	guardSpan.SetAttributes(
		attribute.String("guard.apex", apex),
		attribute.String("guard.verdict", guard.Verdict),
	)
	guardSpan.End()
	switch guard.Verdict {
	case "real":
		scanMetrics.IncGuard("allowlisted")
		scanMetrics.IncOutcome("guard_allowlisted")
		out.GuardHit = "allowlisted"
		out.Label = "legitimate"
		span.SetAttributes(
			attribute.String("scan.outcome", "guard_allowlisted"),
			attribute.String("scan.label", out.Label),
		)
		cacheSet(ctx, cacheKey, out)
		return out, nil
	case "typosquat":
		scanMetrics.IncGuard("typosquat")
		scanMetrics.IncOutcome("guard_typosquat")
		out.GuardHit = "typosquat:" + guard.MatchedBrand
		out.Score = 100
		out.Probability = 1.0
		out.Label = "phishing"
		span.SetAttributes(
			attribute.String("scan.outcome", "guard_typosquat"),
			attribute.String("guard.matched_brand", guard.MatchedBrand),
			attribute.String("scan.label", out.Label),
		)
		cacheSet(ctx, cacheKey, out)
		return out, nil
	}

	_, subSpan := pipelineTracer.Start(guardCtx, "svc-03.pipeline.guard.CheckSubdomainBrand")
	hostname := url.HostnameFromURL(normalized)
	sub := url.CheckSubdomainBrand(hostname)
	subSpan.SetAttributes(attribute.String("guard.verdict", sub.Verdict))
	subSpan.End()
	if sub.Verdict == "brand-in-subdomain" {
		scanMetrics.IncGuard("brand_in_subdomain")
		scanMetrics.IncOutcome("guard_brand")
		out.GuardHit = "brand-in-subdomain:" + sub.MatchedBrand
		out.Score = 100
		out.Probability = 1.0
		out.Label = "phishing"
		span.SetAttributes(
			attribute.String("scan.outcome", "guard_brand"),
			attribute.String("guard.matched_brand", sub.MatchedBrand),
			attribute.String("scan.label", out.Label),
		)
		cacheSet(ctx, cacheKey, out)
		return out, nil
	}
	scanMetrics.IncGuard("none")

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
		l1Ctx, l1Span := pipelineTracer.Start(predCtx, "svc-03.pipeline.l1")
		mlScore, mlProb, routed, reason, _ = urlModel.PredictWithRoute(l1Ctx, normalized)
		l1Span.SetAttributes(
			attribute.Int("l1.score", mlScore),
			attribute.Float64("l1.probability", mlProb),
			attribute.Bool("l1.routed_to_enrichment", routed),
		)
		l1Span.End()
	}()
	go func() {
		defer wg.Done()
		// TIChecker.Check opens its own span; no need to wrap.
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
	out.tiIndicatorID = tiRes.IndicatorID

	// Prior-email reuse: if this URL was enriched recently for another email,
	// skip the live L2 enrichment fetch and reuse the stored signal.
	priorReuse := priorEnrichmentFresh(ctx, raw)

	// Layer 2: ML phishing check fires when TI didn't match OR when TI
	// matched with low confidence (< 80 risk). classifyLabel ignores
	// low-confidence TI matches, so we still want L2 to weigh in.
	var enrichment *enricher.EnrichedURL
	ranL2 := false
	if !priorReuse && (!tiRes.Matched || tiRes.RiskScore < 80) && phishingDetector != nil {
		reasonLabel := "ti_miss"
		if tiRes.Matched {
			reasonLabel = "ti_low_confidence"
		}
		scanMetrics.IncL2(reasonLabel)
		ranL2 = true

		mlCtx, mlCancel := context.WithTimeout(ctx, 15*time.Second)
		defer mlCancel()
		if phishResult, eu, phishErr := phishingDetector.ScoreDetailed(mlCtx, normalized); phishErr != nil {
			scanMetrics.IncStageError("l2")
			span.RecordError(phishErr)
			log.Warn().Err(phishErr).Str("url", normalized).Msg("phishing ML check failed")
		} else {
			out.MLDeployP = phishResult.DeployP
			out.MLVerdict = phishResult.Verdict
			out.MLCacheHit = phishResult.CacheHit
			out.urlP = phishResult.URLP
			out.opP = phishResult.OpP
			out.deployP = phishResult.DeployP
			enrichment = eu
		}
	}

	out.Label = classifyLabel(mlScore, tiRes, routed, out.MLVerdict)

	outcome := "fallback_legitimate"
	switch {
	case tiRes.Matched && tiRes.RiskScore >= 80:
		outcome = "ti_phishing"
	case ranL2 && out.MLVerdict == "phishing":
		outcome = "ml_phishing"
	case ranL2 && out.MLVerdict == "benign":
		outcome = "ml_benign"
	case priorReuse:
		outcome = "prior_reuse"
	case tiRes.Matched:
		outcome = "ti_low_confidence"
	}
	scanMetrics.IncOutcome(outcome)
	span.SetAttributes(
		attribute.String("scan.outcome", outcome),
		attribute.String("scan.label", out.Label),
	)

	cacheSet(ctx, cacheKey, out)
	return out, enrichment
}

// urlScoreKey is the Valkey key for a normalized URL's cached scan.
func urlScoreKey(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return "url_score:" + hex.EncodeToString(sum[:])
}

// cacheGet returns a cached scan for key, or ok=false on miss / any error
// (the cache is an optimisation; failures degrade to a fresh scan).
func cacheGet(ctx context.Context, key string) (urlScan, bool) {
	if urlCache == nil {
		return urlScan{}, false
	}
	val, err := urlCache.Do(ctx, urlCache.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return urlScan{}, false // miss or error
	}
	var s urlScan
	if json.Unmarshal([]byte(val), &s) != nil {
		return urlScan{}, false
	}
	return s, true
}

// cacheSet stores a scan under key with the url_score TTL. Best-effort.
func cacheSet(ctx context.Context, key string, s urlScan) {
	if urlCache == nil {
		return
	}
	body, err := json.Marshal(s)
	if err != nil {
		return
	}
	cmd := urlCache.B().Set().Key(key).Value(string(body)).ExSeconds(int64(urlScoreTTL.Seconds())).Build()
	_ = urlCache.Do(ctx, cmd).Error()
}

// priorEnrichmentFresh reports whether rawURL already has an enriched_threats
// row checked within priorEnrichmentTTL, so the live L2 enrichment can be
// skipped. Any lookup error degrades to false (enrich normally).
func priorEnrichmentFresh(ctx context.Context, rawURL string) bool {
	if dbPool == nil {
		return false
	}
	row, err := dbsqlc.New(dbPool).GetEnrichedThreatByURL(ctx, rawURL)
	if err != nil || !row.LastChecked.Valid {
		return false
	}
	return time.Since(row.LastChecked.Time) < priorEnrichmentTTL
}

// persistEnrichment writes enrichment for the freshly-scored URLs of an email.
// It is best-effort: errors are logged and metered but never block scores.url.
func persistEnrichment(
	ctx context.Context,
	emailID int64,
	fetchedAt time.Time,
	scans []urlScan,
	enrichments []*enricher.EnrichedURL,
	log zerolog.Logger,
) {
	if enrichWriter == nil {
		return
	}
	records := make([]persist.ScanRecord, 0, len(scans))
	for i, s := range scans {
		if !s.fresh || s.Normalized == "" {
			continue // cache hit or unparseable URL — nothing new to persist
		}
		records = append(records, persist.ScanRecord{
			URL:           s.URL,
			RiskScore:     s.Score,
			URLP:          s.urlP,
			OpP:           s.opP,
			DeployP:       s.deployP,
			Verdict:       s.MLVerdict,
			TIMatched:     s.TIMatch,
			TIIndicatorID: s.tiIndicatorID,
			Enrichment:    enrichments[i],
		})
	}
	if len(records) == 0 {
		return
	}
	if err := enrichWriter.Persist(ctx, emailID, fetchedAt, records); err != nil {
		scanMetrics.IncPersistError()
		log.Warn().Err(err).Int64("email_id", emailID).Msg("enrichment persistence failed (scores.url still published)")
	}
}

// classifyLabel maps ML + TI + Layer-2 signals to a label.
// mlVerdict is the fusion scorer verdict ("phishing" | "benign" | "").
func classifyLabel(mlScore int, ti url.TIResult, routed bool, mlVerdict string) string {
	if ti.Matched && ti.RiskScore >= 80 {
		return "phishing"
	}
	if mlVerdict == "phishing" {
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
