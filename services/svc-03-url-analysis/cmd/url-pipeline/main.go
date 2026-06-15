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

	// l2Timeout bounds a single Layer-2 call (live enrichment + the sidecar
	// inference call). It must exceed the enricher's own ~2s internal cap PLUS
	// the sidecar reserve (internal/phishing.l2SidecarReserve) so the detector
	// can give enrichment its full budget and still hold back a slice for the
	// sidecar /score-features call. At 1500ms a slow enrichment consumed the
	// whole budget and the sidecar call then failed with "context deadline
	// exceeded" — leaving no L2 verdict, so a high L1 benign over-flag (98-100)
	// stood and drove a false phishing verdict. The worst-case per-URL latency
	// rises to ~2.5s, which is acceptable on this async pipeline (most legitimate
	// mail still early-exits before L2 — see l1Confident).
	l2Timeout = 2500 * time.Millisecond

	// L2 early-exit thresholds. The expensive L2 network enricher only adds
	// value in the genuinely-uncertain or looks-phishing band; when L1 is clearly
	// BENIGN we skip it entirely (the biggest latency win — most legitimate-mail
	// URLs never touch the network). A domain-guard hit already returns before L2
	// is considered. We deliberately do NOT early-exit on a high L1 score: the L1
	// model over-flags obscure benign domains, so a "looks-phishing" L1 must be
	// verified by L2 before it can drive a high url_risk.
	//
	//   l1ConfidentPhishingScore: retained as the documented "L1 looks strongly
	//     phishing" reference point (mirrors classifyLabel's >=70 phishing cut,
	//     with margin). It no longer triggers an L2 skip — those URLs run L2.
	//   l1ConfidentBenignScore: L1 score at/below which we trust the benign call
	//     without L2 (well under classifyLabel's 40 suspicious cut).
	l1ConfidentPhishingScore = 85
	l1ConfidentBenignScore   = 20

	// uncorroboratedScore is the score an UNCORROBORATED ML "phishing" URL is
	// capped to (see isUncorroboratedPhishing). Both the L1 structural model and
	// the L2 fusion model over-flag live but benign URLs (mailing-list / ~user /
	// IP-literal / query-string newsletter links): on the easy_ham corpus they
	// scored such URLs at L1=100 AND L2 deploy_p~0.84 (op_p~0.85), so an op_p-based
	// "corroboration" test (the original #209 floor) could not separate them from
	// real phish. A phishing-grade url_risk therefore now requires a RELIABLE
	// signal — a TI blocklist hit (>=80) or the typosquat / brand-in-subdomain
	// guard (which short-circuits earlier). An ML-only "phishing" call is capped
	// here: low enough that it cannot, alone, blend an otherwise-benign email past
	// svc-08's benign band (a benign easy_ham email blends url+header+nlp; at
	// url=25 the URL contributes its 0.35 weight without tipping the verdict), yet
	// non-zero so a genuinely odd URL still carries a mild signal into fusion. A
	// TI/guard-confirmed phish keeps its 100. (Tuned down from 40 so the capped
	// URL clears svc-08's <=25 benign band rather than landing mid-"suspicious".)
	uncorroboratedScore = 25
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
	MLDeployP float64 `json:"ml_deploy_p,omitempty"`
	// MLOpP is the L2 operational-feature probability (DNS/WHOIS/TLS/HTTP/GeoIP),
	// retained for observability/Jaeger. It is NOT used to gate the phishing
	// verdict: live benign hosts (mailing lists, blogs) score op_p ~0.85 just like
	// real phish, so it cannot corroborate a phishing call (see
	// isUncorroboratedPhishing).
	MLOpP      float64 `json:"ml_op_p,omitempty"`
	MLVerdict  string  `json:"ml_verdict,omitempty"`
	MLCacheHit bool    `json:"ml_cache_hit,omitempty"`
	// MLDegraded is set when the L2 verdict is a fail-open default (breaker open)
	// rather than a real model score. A degraded benign verdict is NOT evidence
	// of benignity, so classifyLabel must not let it de-escalate a high L1 score.
	MLDegraded bool   `json:"ml_degraded,omitempty"`
	Label      string `json:"label"`
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
			// fallback marks the URL component as a degraded best-effort score when
			// Layer-2 was unavailable for one or more scored URLs (sidecar
			// timeout/outage). svc-07 lifts this into
			// emails.scored.degraded_components so the partial L2 signal is visible
			// to operators and downstream — without forcing PartialAnalysis, since a
			// URL score is still present.
			"fallback": anyURLDegraded(scans),
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
	// only skip it on the confident-BENIGN side. When L1 is clearly benign
	// (<= l1ConfidentBenignScore) AND there's no low-confidence TI hint pulling
	// the verdict the other way, we trust the cheap verdict and skip the network
	// entirely. A high L1 score does NOT skip L2: the L1 model over-flags obscure
	// benign domains, so a "looks-phishing" L1 must be verified by L2 before it
	// can drive a high url_risk (the benign false-positive fix). A low-confidence
	// TI match (Matched but <80) keeps us in the uncertain band so L2 can
	// corroborate. The latency win still covers most legitimate-mail URLs, which
	// score clearly benign and never touch the network.
	ranL2 := false
	l2Skipped := false
	l2Candidate := (!tiRes.Matched || tiRes.RiskScore < 80) && phishingDetector != nil
	if l2Candidate && l1Confident(mlScore, routed, tiRes) {
		l2Skipped = true
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
			// L2 produced no verdict. Mark the result degraded so the missing L2
			// signal is visible downstream (it bubbles up to the scores.url
			// "fallback" flag → emails.scored.degraded_components) instead of
			// looking like a clean scan. With no L2 verdict the URL is ML-only and
			// therefore uncorroborated, so it is capped to the suspicious band below
			// (it cannot drive a phishing verdict without TI/guard) — which also
			// means an L2 outage degrades gracefully instead of silently flipping
			// verdicts.
			out.MLDegraded = true
			log.Warn().Err(phishErr).Str("url", normalized).Msg("phishing ML check failed")
		} else {
			out.MLDeployP = phishResult.DeployP
			out.MLOpP = phishResult.OpP
			out.MLVerdict = phishResult.Verdict
			out.MLCacheHit = phishResult.CacheHit
			out.MLDegraded = phishResult.Degraded
		}
	}

	out.Label = classifyLabel(mlScore, tiRes, routed, out.MLVerdict, out.MLDegraded)

	// Reconcile the numeric envelope score with the label. svc-07 fuses
	// env.Score numerically and never consults the label, so the number must
	// track the verdict:
	//   - A phishing label pins Score=100 so a confirmed phish whose raw L1 score
	//     may be low is not under-weighted downstream.
	//   - A URL the L2 enricher genuinely cleared to benign must NOT keep its raw
	//     L1 structural score: the L1 model over-flags obscure benign domains at
	//     ~100, and leaving that number in place would re-flag the email even
	//     though the label is legitimate. We pull the score down to L2's deploy_p,
	//     the network-enriched estimate that just cleared it.
	out.Score, out.Probability = envelopeScore(
		out.Label, out.Score, out.Probability,
		out.MLVerdict, out.MLDegraded, out.MLDeployP,
	)

	// Corroboration gate — the benign over-flag fix. Only a RELIABLE signal may
	// drive an elevated url_risk: a TI blocklist hit (>=80) or the typosquat /
	// brand-in-subdomain guard (which short-circuits earlier, so here it means
	// TI). Both ML models over-flag live-but-benign URLs — on the easy_ham corpus
	// the L1 structural model scored ordinary mailing-list / ~user / IP-literal /
	// query-string newsletter links at ~100, and the L2 fusion model independently
	// scored those same reachable hosts as phishing with high op_p (~0.85) and
	// deploy_p (~0.84) — so an op_p floor (the original #209 corroboration test)
	// cannot tell them from real phish. Any uncorroborated result is therefore
	// capped to uncorroboratedScore and demoted out of the phishing band.
	//
	// Recall is preserved: a TI/guard-confirmed phish keeps its 100, and an
	// ML-only phish is still flagged (as suspicious) and still feeds fusion — it
	// just cannot single-handedly pin the email to a phishing verdict.
	deescalated := false
	if !urlCorroborated(tiRes) && out.Score > uncorroboratedScore {
		deescalated = true
		if out.Label == "phishing" {
			out.Label = "suspicious"
		}
		out.Score = uncorroboratedScore
		out.Probability = float64(uncorroboratedScore) / 100.0
		span.SetAttributes(
			attribute.Bool("scan.url_uncorroborated_deescalated", true),
			attribute.Float64("scan.l2_op_p", out.MLOpP),
		)
	}

	// Exactly one outcome is recorded per scan — scans_total is a per-scan
	// counter, so the path flags (de-escalation, L2 skip) are folded into this
	// single switch instead of being incremented separately (which would
	// double-count the scan). Order: verdict-shaping outcomes first, then the
	// L2-error and latency-skip paths.
	outcome := "fallback_legitimate"
	switch {
	case deescalated:
		outcome = "uncorroborated_deescalated"
	case tiRes.Matched && tiRes.RiskScore >= 80:
		outcome = "ti_phishing"
	case ranL2 && out.MLVerdict == "phishing":
		outcome = "ml_phishing"
	case ranL2 && out.MLVerdict == "benign":
		outcome = "ml_benign"
	case ranL2:
		// L2 ran but produced no verdict (errored/timed out). Distinct from
		// fallback_legitimate so the outage path is visible in metrics/traces.
		outcome = "l2_error"
	case tiRes.Matched:
		outcome = "ti_low_confidence"
	case l2Skipped:
		outcome = "l2_skipped_confident"
	}
	scanMetrics.IncOutcome(outcome)
	span.SetAttributes(
		attribute.String("scan.outcome", outcome),
		attribute.String("scan.label", out.Label),
	)

	return out
}

// classifyLabel maps ML + TI + Layer-2 signals to a label.
// mlVerdict is the fusion scorer verdict ("phishing" | "benign" | ""); mlDegraded
// is true when that verdict is a fail-open default (breaker open) rather than a
// real score.
//
// L2 is the network-enriched authority in the uncertain/looks-phishing band: a
// genuine L2 benign verdict (ran and scored, not degraded) is strictly more
// informed than the L1 structural guess, so it MUST be able to de-escalate a
// high L1 score. Without this, a benign URL the L1 model over-flags (>=70) is
// pinned to "phishing" even after L2 correctly clears it — the source of the
// benign URL false positives. A TI hit (>=80) still wins outright, and a degraded
// (breaker-open) benign verdict carries no signal, so the L1 score stands.
func classifyLabel(mlScore int, ti url.TIResult, routed bool, mlVerdict string, mlDegraded bool) string {
	if ti.Matched && ti.RiskScore >= 80 {
		return "phishing"
	}
	if mlVerdict == "phishing" {
		return "phishing"
	}
	// A real (non-degraded) L2 benign verdict overrides the L1 structural score:
	// the network enricher cleared the URL, so don't escalate on L1 alone.
	if mlVerdict == "benign" && !mlDegraded {
		return "legitimate"
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

// envelopeScore reconciles the numeric envelope score with the final label so
// the number svc-07 fuses on tracks the verdict.
//
//   - label "phishing": pin Score=100 (a TI/L2-confirmed phish must not be
//     under-weighted by a low raw L1 score).
//   - a genuine (non-degraded) L2 benign verdict: the network enricher cleared
//     the URL, so replace the raw L1 score — which over-flags obscure benign
//     domains near 100 — with L2's deploy_p estimate. Without this, a corrected
//     label is legitimate but the leftover L1 score still flags the email.
//   - otherwise: keep the L1-derived score/probability unchanged.
//
// mlDegraded guards the L2 branch: a fail-open (breaker-open) benign verdict
// carries no real signal, so it must NOT pull the score down — the L1 score
// stands and phishing recall is preserved during a network outage.
func envelopeScore(
	label string,
	score int, prob float64,
	mlVerdict string, mlDegraded bool, mlDeployP float64,
) (int, float64) {
	if label == "phishing" {
		return 100, 1.0
	}
	if mlVerdict == "benign" && !mlDegraded {
		l2Score := int(mlDeployP * 100)
		// Only ever pull the score DOWN. If the L1 score was already at/below the
		// L2 estimate (genuinely-benign URL), keep it — never inflate.
		if l2Score < score {
			return l2Score, mlDeployP
		}
	}
	return score, prob
}

// l1Confident reports whether the cheap signals (L1 XGBoost score + routing
// flag, no TI match) already place a URL clearly in the BENIGN band, so the L2
// network enricher can be skipped. A URL routed-to-enrichment or with any TI hit
// is NOT confident — those stay in the uncertain band so L2 weighs in.
//
// We intentionally early-exit ONLY on the confident-benign side. The L1 model is
// the dominant false-positive source on real benign mail (obscure/dead domains
// scored 100), so a high L1 score is NOT trustworthy on its own — those URLs must
// always run L2 so the network-enriched verdict can corroborate or correct the
// structural guess. The latency win is preserved where it is safe: the common
// case (clearly-benign mail, mlScore <= l1ConfidentBenignScore) still skips the
// network. l1ConfidentPhishingScore is retained for the test/threshold surface.
func l1Confident(mlScore int, routed bool, ti url.TIResult) bool {
	if ti.Matched || routed {
		return false
	}
	return mlScore <= l1ConfidentBenignScore
}

// urlCorroborated reports whether a URL carries a RELIABLE signal that justifies
// an elevated (above uncorroboratedScore) url_risk: a high-confidence TI
// blocklist hit. The typosquat / brand-in-subdomain guard is the other reliable
// signal, but it short-circuits scoring earlier (its hits never reach the
// corroboration gate), so at this point a TI hit (>=80) is the test.
//
// Without corroboration a URL is ML-only, and both ML models over-flag
// live-but-benign URLs (the L1 structural model scores ordinary mailing-list /
// ~user / IP-literal / query-string newsletter links at ~100, and the L2 fusion
// model independently scores those same reachable hosts as phishing with high
// op_p ~0.85 / deploy_p ~0.84), so an ML-only result is capped — see the
// corroboration gate in scanOne.
func urlCorroborated(ti url.TIResult) bool {
	return ti.Matched && ti.RiskScore >= 80
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

// anyURLDegraded reports whether any scanned URL has a degraded Layer-2 result
// (the L2 verdict was a fail-open default or the sidecar call failed). It drives
// the scores.url "fallback" flag so svc-07 records the URL component as degraded
// in emails.scored.degraded_components.
func anyURLDegraded(scans []urlScan) bool {
	for _, s := range scans {
		if s.MLDegraded {
			return true
		}
	}
	return false
}

// worseLabel returns the more severe of two label values.
func worseLabel(a, b string) string {
	rank := map[string]int{"legitimate": 0, "suspicious": 1, "phishing": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
