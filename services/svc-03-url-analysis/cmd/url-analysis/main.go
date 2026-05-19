package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/internal/phishing"
	urlpkg "github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
	"github.com/saif/cybersiren/shared/config"
	sharedhttp "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
	"github.com/saif/cybersiren/shared/postgres/repository"
	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

// urlPredictor abstracts the URL model so the handler is testable without a
// real Python worker.
type urlPredictor interface {
	PredictWithRoute(ctx context.Context, url string) (score int, prob float64, routed bool, reason string, err error)
}

// tiLookup abstracts the TI checker for testing without Valkey/Postgres.
type tiLookup interface {
	Check(ctx context.Context, url string) (urlpkg.TIResult, error)
}

// phishingScorer abstracts the Layer-2 ML detector for testing without GeoIP
// databases or a running Python sidecar.
type phishingScorer interface {
	Score(ctx context.Context, rawURL string) (phishing.Result, error)
}

func main() {
	bootstrapLog := logger.New("info", true)

	cfg, err := config.Load()
	if err != nil {
		bootstrapLog.Fatal().Err(err).Msg("failed to load config")
		return
	}

	if err := cfg.Validate(); err != nil {
		bootstrapLog.Fatal().Err(err).Msg("invalid config")
		return
	}

	log := logger.New(cfg.Log.Level, cfg.Log.Pretty)
	logger.SetGlobal(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tracerShutdown, err := tracing.Init(ctx, "svc-03-url-analysis", cfg.JaegerEndpoint)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize tracing")
		return
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := tracerShutdown(shutdownCtx); shutdownErr != nil {
			log.Error().Err(shutdownErr).Msg("tracer shutdown error")
		}
	}()

	reg := metrics.Init("svc-03-url-analysis")

	metricsShutdown, err := metrics.StartServer(cfg.MetricsPort, reg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start metrics server")
		return
	}
	defer func() { _ = metricsShutdown(context.Background()) }()

	poolOpts := pool.PoolOptions{
		MaxConns:          int32(cfg.DB.MaxConns),
		MinConns:          int32(cfg.DB.MinConns),
		MaxConnLifetime:   cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
	}
	dbPool := pool.MustNew(ctx, cfg.DB.DSN(), poolOpts, log)
	defer dbPool.Close()

	// Valkey is optional: if unavailable (e.g. local dev without infra), TI
	// checking is disabled for the session and all lookups return no-match.
	var tiLookupInst tiLookup
	valkeyClient, valkeyErr := sharedvalkey.New(sharedvalkey.ClientOptions{
		Addr:     cfg.Valkey.Addr,
		Password: cfg.Valkey.Password,
		DB:       cfg.Valkey.DB,
	}, log)
	if valkeyErr != nil {
		log.Warn().Err(valkeyErr).Msg("valkey unavailable; TI lookups disabled for this session")
		tiLookupInst = &noopTILookup{}
	} else {
		defer valkeyClient.Close()
		tiRepo := repository.NewTIRepository(dbPool, log, reg)
		tiCache := sharedvalkey.NewTICache(valkeyClient, tiRepo, log, reg, 0)
		if cacheErr := tiCache.RefreshDomainCache(ctx); cacheErr != nil {
			log.Error().Err(cacheErr).Msg("initial TI domain cache refresh failed")
		}
		tiLookupInst = urlpkg.NewTIChecker(tiCache, log)
		log.Info().Msg("TI checker ready")
	}

	// Dev-only TI override: when CYBERSIREN_DEV_MODE=true and
	// CYBERSIREN_TI__OVERRIDE_JSON points to a readable file, swap the live TI
	// checker for one that returns hardcoded results from that file. Used by
	// the e2e test harness (services/svc-03-url-analysis/tests/e2e/run.sh).
	if os.Getenv("CYBERSIREN_DEV_MODE") == "true" {
		if path := os.Getenv("CYBERSIREN_TI__OVERRIDE_JSON"); path != "" {
			override, overrideErr := newJSONTILookup(path)
			if overrideErr != nil {
				log.Fatal().Err(overrideErr).Str("path", path).Msg("failed to load TI override fixture")
				return
			}
			tiLookupInst = override
			log.Warn().Str("path", path).Int("entries", override.size()).Msg("TI checker overridden by dev-only JSON fixture")
		}
	}

	model, err := urlpkg.NewURLModel(cfg.ML.URLModelPath, cfg.ML.URLModelPoolSize, func(msg string, modelErr error) {
		log.Error().Err(modelErr).Str("component", "url_model").Msg(msg)
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize URL model")
		return
	}
	defer model.Close()

	// Layer-2 ML phishing detector (fail-open: starts even if GeoIP unavailable).
	det, detErr := phishing.NewDetector(phishing.Config{
		SidecarURL: cfg.Phishing.SidecarURL,
		GeoIPDir:   cfg.Phishing.GeoIPDir,
		Threshold:  cfg.Phishing.Threshold,
	})
	var scorer phishingScorer
	if detErr != nil {
		log.Warn().Err(detErr).Msg("phishing ML detector init failed; Layer-2 scoring disabled")
	} else {
		scorer = det
		defer det.Close()
		log.Info().
			Str("sidecar", cfg.Phishing.SidecarURL).
			Str("geoip_dir", cfg.Phishing.GeoIPDir).
			Msg("phishing ML detector ready")
	}

	srv := sharedhttp.NewDefaultServer()

	srv.Engine().Static("/static", "./static")
	srv.Engine().GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
	srv.Engine().GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	srv.POST("/scan", scanHandler(model, tiLookupInst, scorer, log))

	go func() {
		if srvErr := srv.Start(fmt.Sprintf(":%d", cfg.Server.Port)); srvErr != nil {
			log.Error().Err(srvErr).Msg("http server error")
		}
	}()

	log.Info().
		Int("port", cfg.Server.Port).
		Int("metrics_port", cfg.MetricsPort).
		Msg("svc-03-url-analysis started")

	<-ctx.Done()
	log.Info().Msg("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("http server shutdown error")
	}

	log.Info().Msg("shutdown complete")
}

// noopTILookup satisfies tiLookup when Valkey is not available.
// All URLs return no-match; no error is surfaced to the caller.
type noopTILookup struct{}

func (n *noopTILookup) Check(_ context.Context, _ string) (urlpkg.TIResult, error) {
	return urlpkg.TIResult{}, nil
}

// jsonTILookup is a dev-only tiLookup that returns hardcoded TIResult values
// loaded from a JSON fixture file. URLs absent from the fixture return
// no-match (same as noopTILookup). Gated behind CYBERSIREN_DEV_MODE=true.
type jsonTILookup struct {
	entries map[string]urlpkg.TIResult
}

type jsonTILookupEntry struct {
	Matched    bool   `json:"matched"`
	Domain     string `json:"domain"`
	RiskScore  int    `json:"risk_score"`
	ThreatType string `json:"threat_type"`
}

func newJSONTILookup(path string) (*jsonTILookup, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ti override fixture: %w", err)
	}
	var rawEntries map[string]jsonTILookupEntry
	if jsonErr := json.Unmarshal(raw, &rawEntries); jsonErr != nil {
		return nil, fmt.Errorf("parse ti override fixture: %w", jsonErr)
	}
	entries := make(map[string]urlpkg.TIResult, len(rawEntries))
	for url, e := range rawEntries {
		entries[url] = urlpkg.TIResult{
			Matched:    e.Matched,
			Domain:     e.Domain,
			RiskScore:  e.RiskScore,
			ThreatType: e.ThreatType,
		}
	}
	return &jsonTILookup{entries: entries}, nil
}

func (j *jsonTILookup) Check(_ context.Context, url string) (urlpkg.TIResult, error) {
	if r, ok := j.entries[url]; ok {
		return r, nil
	}
	return urlpkg.TIResult{}, nil
}

func (j *jsonTILookup) size() int { return len(j.entries) }

type scanRequest struct {
	URL string `json:"url"`
}

type scanResponse struct {
	URL          string  `json:"url"`
	Score        int     `json:"score"`
	Probability  float64 `json:"probability"`
	Label        string  `json:"label"`
	Routed       bool    `json:"routed_to_enrichment"`
	RouteReason  string  `json:"route_reason,omitempty"`
	TIMatch      bool    `json:"ti_match"`
	TIThreatType string  `json:"ti_threat_type"`
	TIRiskScore  int     `json:"ti_risk_score"`
	Degraded     bool    `json:"degraded"`
	// GuardHit is set when the domain guard short-circuits scoring.
	// "allowlisted" means the apex domain is in the known-good set.
	// "typosquat:<brand>" means it closely resembles a known brand.
	GuardHit string `json:"guard_hit,omitempty"`
	// Layer-2 fields — populated only when TI feed does not match.
	MLDeployP  float64 `json:"ml_deploy_p,omitempty"`
	MLVerdict  string  `json:"ml_verdict,omitempty"`
	MLCacheHit bool    `json:"ml_cache_hit,omitempty"`
}

func scanHandler(model urlPredictor, ti tiLookup, scorer phishingScorer, log zerolog.Logger) sharedhttp.HandlerFunc {
	return func(ctx sharedhttp.Context) {
		var req scanRequest
		if reqErr := ctx.ParseJSON(&req); reqErr != nil {
			_ = ctx.RequestError(reqErr)
			return
		}
		if req.URL == "" {
			_ = ctx.Error(http.StatusBadRequest, "bad_request", "url is required")
			return
		}

		normalized, err := normalization.NormalizeURL(req.URL)
		if err != nil {
			_ = ctx.Error(http.StatusBadRequest, "bad_request", fmt.Sprintf("invalid URL: %s", err.Error()))
			return
		}

		// Domain guard: fast-path known-good domains and phishing patterns before
		// touching the ML model or sidecar. L1 score is not used for
		// user-submitted scan labels — only TI + L2 drive the verdict.
		apex := urlpkg.ApexFromURL(normalized)
		guard := urlpkg.CheckDomain(apex)
		switch guard.Verdict {
		case "real":
			_ = ctx.OK(scanResponse{
				URL:      normalized,
				Label:    "legitimate",
				GuardHit: "allowlisted",
			})
			return
		case "typosquat":
			_ = ctx.OK(scanResponse{
				URL:         normalized,
				Score:       100,
				Probability: 1.0,
				Label:       "phishing",
				GuardHit:    "typosquat:" + guard.MatchedBrand,
			})
			return
		}

		// Brand-in-subdomain check: fires before ML when apex is unknown.
		// Catches patterns like "paypal-security.verify-login.com" where the
		// brand appears in a subdomain label but the registered domain is foreign.
		hostname := urlpkg.HostnameFromURL(normalized)
		if sub := urlpkg.CheckSubdomainBrand(hostname); sub.Verdict == "brand-in-subdomain" {
			_ = ctx.OK(scanResponse{
				URL:         normalized,
				Score:       100,
				Probability: 1.0,
				Label:       "phishing",
				GuardHit:    "brand-in-subdomain:" + sub.MatchedBrand,
			})
			return
		}

		var (
			rawScore int
			rawProb  float64
			routed   bool
			reason   string
			tiResult urlpkg.TIResult
			wg       sync.WaitGroup
		)

		wg.Add(2)

		go func() {
			defer wg.Done()
			// L1 model still called for degraded-mode detection and routing
			// transparency, but its score is NOT used in classifyLabel for
			// user-submitted URLs (it was calibrated on feed data, not live scans).
			rawScore, rawProb, routed, reason, _ = model.PredictWithRoute(ctx.Request().Context(), normalized)
		}()

		go func() {
			defer wg.Done()
			tiResult, _ = ti.Check(ctx.Request().Context(), normalized)
		}()

		wg.Wait()

		resp := scanResponse{
			URL:          normalized,
			Score:        rawScore,
			Probability:  rawProb,
			Routed:       routed,
			RouteReason:  reason,
			TIMatch:      tiResult.Matched,
			TIThreatType: tiResult.ThreatType,
			TIRiskScore:  tiResult.RiskScore,
			Degraded:     rawScore == 50 && rawProb == 0.5,
		}

		// Layer 2: ML phishing check fires when TI didn't match OR when TI
		// matched with low confidence (< 80 risk). A low-confidence TI hit
		// alone is not enough to label phishing in classifyLabel, so we still
		// want L2 to weigh in.
		if (!tiResult.Matched || tiResult.RiskScore < 80) && scorer != nil {
			mlCtx, mlCancel := context.WithTimeout(ctx.Request().Context(), 45*time.Second)
			defer mlCancel()
			if phishResult, phishErr := scorer.Score(mlCtx, normalized); phishErr != nil {
				log.Warn().Err(phishErr).Str("url", normalized).Msg("phishing ML check failed")
			} else {
				resp.MLDeployP = phishResult.DeployP
				resp.MLVerdict = phishResult.Verdict
				resp.MLCacheHit = phishResult.CacheHit
			}
		}

		// L1 score overridden to 0 for user-submitted scans — label is driven
		// by TI match and L2 fusion verdict only.
		resp.Label = classifyLabel(0, tiResult, false, resp.MLVerdict)

		log.Debug().
			Str("url", normalized).
			Int("ml_score", rawScore).
			Float64("ml_prob", rawProb).
			Bool("routed", routed).
			Str("route_reason", reason).
			Bool("ti_match", tiResult.Matched).
			Str("ti_threat", tiResult.ThreatType).
			Int("ti_risk", tiResult.RiskScore).
			Str("ml2_verdict", resp.MLVerdict).
			Str("label", resp.Label).
			Bool("degraded", resp.Degraded).
			Msg("scan complete")

		_ = ctx.OK(resp)
	}
}

// classifyLabel maps Layer-1 (ML score + TI) and Layer-2 (fusion ML verdict)
// signals to a final label.
// mlVerdict is "phishing" | "benign" | "" (empty means Layer 2 did not run).
func classifyLabel(mlScore int, ti urlpkg.TIResult, routed bool, mlVerdict string) string {
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
