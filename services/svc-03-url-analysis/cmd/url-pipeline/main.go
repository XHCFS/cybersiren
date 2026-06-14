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
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"

	"github.com/saif/cybersiren/internal/phishing"
	phclient "github.com/saif/cybersiren/internal/phishing/client"
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

	// maxURLsPerEmail caps how many distinct URLs we score per email. A single
	// crafted email can carry dozens of URLs; without a cap one email could
	// monopolise the consumer. After dedup we keep the first N in order.
	maxURLsPerEmail = 15
	// maxURLConcurrency bounds the number of URLs scanned in parallel for one
	// email. It also sets the default L1 model pool size so concurrent L1 calls
	// don't serialise. 8 keeps the worst-case per-email wall-clock at roughly
	// the per-URL latency (a few seconds) rather than N×per-URL.
	maxURLConcurrency = 8

	// l2Timeout bounds a single Layer-2 enrichment call. Lowered from 15s: the
	// enricher's own cap is ~2s, and we want a confirmed worst-case per-URL of
	// ~1.5-2s rather than letting one slow host stall the whole email.
	l2Timeout = 1500 * time.Millisecond

	// L2 early-exit thresholds. The expensive L2 network enricher only adds
	// value in the genuinely-uncertain band; when L1 is already confident we
	// skip it entirely (the biggest latency win — most URLs never touch the
	// network). A domain-guard hit already returns before L2 is considered.
	//
	//   l1ConfidentPhishingScore: L1 XGBoost score at/above which we trust the
	//     phishing call without L2 corroboration (mirrors classifyLabel's >=70
	//     phishing cut, with margin).
	//   l1ConfidentBenignScore: L1 score at/below which we trust the benign call
	//     without L2 (well under classifyLabel's 40 suspicious cut).
	l1ConfidentPhishingScore = 85
	l1ConfidentBenignScore   = 20
)

var (
	urlModel         *url.URLModel
	tiChecker        *url.TIChecker
	phishingDetector *phishing.Detector
	scanMetrics      *url.ScanMetrics
	persister        *persist.Persister
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
				// Match the per-email URL scan concurrency so concurrent L1
				// predictions don't serialize on a smaller worker pool.
				poolSize = maxURLConcurrency
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

			// Enrichment persistence (ARCH-SPEC §14 step 3a). NeedsDB is true, so
			// deps.Pool is set; NewRepoStore wires the org-scoped repository layer
			// (every write tx sets app.current_org_id — G10 RLS). A nil pool would
			// disable persistence rather than crash the consumer.
			if store := persist.NewRepoStore(deps.Pool); store != nil {
				persister = persist.New(store, persist.NewMetrics(deps.Registry), log)
				log.Info().Msg("enrichment persistence ready")
			} else {
				log.Warn().Msg("no DB pool; enrichment persistence disabled")
			}

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
	// TIIndicatorID is the matched ti_indicators.id (0 when the TI cache entry
	// predates the id being stored); persist uses it for the audit row.
	TIIndicatorID int64 `json:"ti_indicator_id,omitempty"`
	// GuardHit is set when the domain guard short-circuits scoring.
	// "allowlisted" / "typosquat:<brand>" / "brand-in-subdomain:<brand>".
	GuardHit string `json:"guard_hit,omitempty"`
	// Layer-2 ML fields — populated only on TI-feed misses.
	MLDeployP  float64 `json:"ml_deploy_p,omitempty"`
	MLVerdict  string  `json:"ml_verdict,omitempty"`
	MLCacheHit bool    `json:"ml_cache_hit,omitempty"`
	Label      string  `json:"label"`
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var input contracts.AnalysisURLs
	if err := json.Unmarshal(msg.Value, &input); err != nil {
		return fmt.Errorf("decode analysis.urls: %w", err)
	}

	log := zerolog.Ctx(ctx).With().Str("email_id", input.Meta.EmailID).Logger()

	// Dedup by normalized form and cap the count per email before scoring.
	// Each scan does live network I/O (DNS/TLS/HTTP), so deduping repeated
	// links and capping a URL-stuffed email is what keeps a single email's
	// wall-clock bounded. We keep the FIRST occurrence (preserving order) and
	// note when we truncated.
	kept, deduped, truncated := dedupAndCapURLs(input.URLs)
	if deduped > 0 || truncated > 0 {
		log.Info().
			Int("urls_in", len(input.URLs)).
			Int("urls_scanned", len(kept)).
			Int("deduped", deduped).
			Int("truncated", truncated).
			Msg("URL list deduped/capped before scoring")
	}

	// Scan the kept URLs concurrently with a bounded semaphore. Results are
	// written to a position-indexed slice (no shared-state race), then the
	// email aggregate is folded serially below — identical output to the old
	// serial loop, just computed in parallel.
	scans := make([]urlScan, len(kept))
	sem := make(chan struct{}, maxURLConcurrency)
	g, gctx := errgroup.WithContext(ctx)
	for i, raw := range kept {
		i, raw := i, raw
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()
			scans[i] = scanOne(gctx, raw, log)
			return nil
		})
	}
	// scanOne never returns an error (it degrades internally), so Wait is only
	// for the barrier; we ignore the (always-nil) error.
	_ = g.Wait()

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

	ft := input.Meta.FetchedAt
	if ft.IsZero() {
		ft = time.Now().UTC()
	}
	out := contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope producer.
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
	if err := prod.Publish(ctx, []byte(input.Meta.EmailID), body, 1); err != nil { // +1 kafka retry
		return fmt.Errorf("publish scores.url: %w", err)
	}

	log.Info().
		Int("urls", len(input.URLs)).
		Int("max_score", maxScore).
		Int("max_ti_risk", maxTIRisk).
		Str("worst_label", worstLabel).
		Msg("scored URLs")

	// Persist enrichment (ARCH-SPEC §14 step 3a). Runs AFTER the scores.url
	// publish so the score is already on the wire before any DB work. All writes
	// are idempotent (bare upsert ON CONFLICT, enriched_threats UPDATE,
	// enrichment_results UPSERT, ti-match ON CONFLICT DO NOTHING), so the
	// at-least-once redelivery of a NACKed message re-converges the writes
	// rather than duplicating, and svc-07 dedups the re-published scores.url. We
	// therefore RETURN a persist failure so the consumer NACKs and redelivery
	// retries the (idempotent) writes — a DB outage must not silently drop the
	// required P1.2 writes. No scoring value is recomputed here.
	if err := persistEnrichment(ctx, input, ft, scans, log); err != nil {
		// Already wrapped by persistEnrichment; returning it NACKs the message.
		return err
	}
	return nil
}

// persistEnrichment projects the in-memory scan results into the persistence
// input and writes them through the org-scoped repository layer. It is a no-op
// (nil error) when persistence is disabled (no DB pool). It returns the first
// write error so handle() can NACK the message and let redelivery retry the
// idempotent writes.
func persistEnrichment(
	ctx context.Context,
	input contracts.AnalysisURLs,
	fetchedAt time.Time,
	scans []urlScan,
	log zerolog.Logger,
) error {
	if persister == nil {
		return nil
	}

	results := make([]persist.URLResult, 0, len(scans))
	for _, s := range scans {
		ref := s.Normalized
		if ref == "" {
			ref = s.URL
		}
		apex := url.ApexFromURL(ref)
		results = append(results, persist.URLResult{
			RawURL:       s.URL,
			Normalized:   s.Normalized,
			Domain:       url.HostnameFromURL(ref),
			TLD:          normalization.TLDLabel(apex),
			Apex:         apex,
			Score:        s.Score,
			Label:        s.Label,
			GuardHit:     s.GuardHit,
			TIMatch:      s.TIMatch,
			TIThreatType: s.TIThreatType,
			TIRiskScore:  s.TIRiskScore,
			// TIIndicatorID carries the matched ti_indicators.id the cache lookup
			// surfaced, so persist writes the email_url_ti_matches audit row. It is
			// zero only for legacy cache entries that predate the id being stored;
			// the audit then skips (persist gates on > 0).
			TIIndicatorID: s.TIIndicatorID,
			MLDeployP:     s.MLDeployP,
			MLVerdict:     s.MLVerdict,
			MLCacheHit:    s.MLCacheHit,
		})
	}

	// Two-id model (G17): SVC-03 keys the email_urls lookup on the DB BIGSERIAL
	// internal_id SVC-02 assigned and carried on analysis.urls. email_id is a
	// UUIDv7 string and can NOT substitute for it, so a zero internal_id stays
	// zero (the persist layer skips a zero-keyed write-back). We do NOT re-derive
	// internal_id via a DB lookup.
	internalID := input.InternalID
	email := persist.Email{
		OrgID:      input.Meta.OrgID,
		InternalID: internalID,
		FetchedAt:  fetchedAt,
		URLs:       results,
	}

	if err := persister.Persist(ctx, email); err != nil {
		log.Warn().Err(err).
			Str("email_id", input.Meta.EmailID).
			Int64("internal_id", internalID).
			Msg("enrichment persistence reported errors (scores already published; NACKing for retry)")
		return fmt.Errorf("persist email enrichment: %w", err)
	}
	return nil
}

// scanOne mirrors the standalone /scan handler: normalise, run ML + TI in
// parallel, classify into a label.
func scanOne(ctx context.Context, raw string, log zerolog.Logger) urlScan {
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
		return out
	}
	out.Normalized = normalized
	span.SetAttributes(attribute.String("scan.url", normalized))

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
		return out
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
		return out
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
		return out
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
	out.TIIndicatorID = tiRes.IndicatorID

	// Layer 2: ML phishing check fires when TI didn't match OR when TI
	// matched with low confidence (< 80 risk). classifyLabel ignores
	// low-confidence TI matches, so we still want L2 to weigh in.
	//
	// Staged early-exit (latency): the L2 enricher does live network I/O, so we
	// only invoke it for the genuinely-uncertain band. When L1 is already
	// confident (clearly phishing >= l1ConfidentPhishingScore or clearly benign
	// <= l1ConfidentBenignScore) AND there's no low-confidence TI hint pulling
	// the verdict the other way, we trust the cheap verdict and skip the network
	// entirely. A low-confidence TI match (Matched but <80) keeps us in the
	// uncertain band so L2 can corroborate. This is the biggest latency win —
	// most URLs never touch the network.
	ranL2 := false
	l2Candidate := (!tiRes.Matched || tiRes.RiskScore < 80) && phishingDetector != nil
	if l2Candidate && l1Confident(mlScore, routed, tiRes) {
		scanMetrics.IncOutcome("l2_skipped_confident")
		span.SetAttributes(attribute.Bool("scan.l2_skipped_confident", true))
		l2Candidate = false
	}
	if l2Candidate {
		reasonLabel := "ti_miss"
		if tiRes.Matched {
			reasonLabel = "ti_low_confidence"
		}
		scanMetrics.IncL2(reasonLabel)
		ranL2 = true

		mlCtx, mlCancel := context.WithTimeout(ctx, l2Timeout)
		defer mlCancel()
		if phishResult, phishErr := phishingDetector.Score(mlCtx, normalized); phishErr != nil {
			scanMetrics.IncStageError("l2")
			span.RecordError(phishErr)
			log.Warn().Err(phishErr).Str("url", normalized).Msg("phishing ML check failed")
		} else {
			out.MLDeployP = phishResult.DeployP
			out.MLVerdict = phishResult.Verdict
			out.MLCacheHit = phishResult.CacheHit
		}
	}

	out.Label = classifyLabel(mlScore, tiRes, routed, out.MLVerdict)

	// A confirmed phishing verdict (TI RiskScore>=80 or the L2 fusion scorer)
	// must carry a high numeric envelope score: svc-07 fuses env.Score
	// numerically and never consults the label, so leaving Score at the raw L1
	// XGBoost value (which can be low even for a TI/L2-confirmed phish) would
	// under-weight the strongest URL signal downstream. Mirror the guard
	// typosquat / brand-in-subdomain branches which already pin Score=100.
	out.Score, out.Probability = phishingScore(out.Label, out.Score, out.Probability)

	outcome := "fallback_legitimate"
	switch {
	case tiRes.Matched && tiRes.RiskScore >= 80:
		outcome = "ti_phishing"
	case ranL2 && out.MLVerdict == "phishing":
		outcome = "ml_phishing"
	case ranL2 && out.MLVerdict == "benign":
		outcome = "ml_benign"
	case tiRes.Matched:
		outcome = "ti_low_confidence"
	}
	scanMetrics.IncOutcome(outcome)
	span.SetAttributes(
		attribute.String("scan.outcome", outcome),
		attribute.String("scan.label", out.Label),
	)

	return out
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

// phishingScore raises the numeric envelope score to a confirmed-phishing
// envelope when the label is "phishing", so a TI/L2-confirmed verdict is not
// under-weighted downstream (svc-07 fuses on the numeric score, not the label).
// Non-phishing labels keep the L1-derived score/probability unchanged.
func phishingScore(label string, score int, prob float64) (int, float64) {
	if label == "phishing" {
		return 100, 1.0
	}
	return score, prob
}

// l1Confident reports whether the cheap signals (L1 XGBoost score + routing
// flag, no TI match) already place a URL clearly in the phishing or benign band,
// so the L2 network enricher can be skipped. A URL routed-to-enrichment or with
// any TI hit is NOT confident — those stay in the uncertain band so L2 weighs in.
func l1Confident(mlScore int, routed bool, ti url.TIResult) bool {
	if ti.Matched || routed {
		return false
	}
	return mlScore >= l1ConfidentPhishingScore || mlScore <= l1ConfidentBenignScore
}

// dedupAndCapURLs normalises each raw URL, drops duplicates that share a
// normalized form (keeping the first raw occurrence), and caps the result at
// maxURLsPerEmail. It returns the kept raw URLs (in first-seen order), the
// number dropped as duplicates, and the number dropped by the cap.
//
// URLs that fail normalisation are kept (deduped on their raw form) so scanOne
// can still record the normalisation failure rather than silently dropping them.
func dedupAndCapURLs(urls []contracts.ExtractedURL) (kept []string, deduped, truncated int) {
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		key := u.URL
		if n, err := normalization.NormalizeURL(u.URL); err == nil {
			key = n
		}
		if _, dup := seen[key]; dup {
			deduped++
			continue
		}
		seen[key] = struct{}{}
		if len(kept) >= maxURLsPerEmail {
			truncated++
			continue
		}
		kept = append(kept, u.URL)
	}
	return kept, deduped, truncated
}

// worseLabel returns the more severe of two label values.
func worseLabel(a, b string) string {
	rank := map[string]int{"legitimate": 0, "suspicious": 1, "phishing": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
