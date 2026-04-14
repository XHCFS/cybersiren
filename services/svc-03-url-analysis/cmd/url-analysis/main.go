package main

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

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

	valkeyClient := sharedvalkey.MustNew(sharedvalkey.ClientOptions{
		Addr:     cfg.Valkey.Addr,
		Password: cfg.Valkey.Password,
		DB:       cfg.Valkey.DB,
	}, log)
	defer valkeyClient.Close()

	tiRepo := repository.NewTIRepository(dbPool, log, reg)
	tiCache := sharedvalkey.NewTICache(valkeyClient, tiRepo, log, reg, 0)

	if cacheErr := tiCache.RefreshDomainCache(ctx); cacheErr != nil {
		log.Error().Err(cacheErr).Msg("initial TI domain cache refresh failed")
	}

	tiChecker := urlpkg.NewTIChecker(tiCache, log)

	model, err := urlpkg.NewURLModel(cfg.ML.URLModelPath, cfg.ML.URLModelPoolSize, func(msg string, modelErr error) {
		log.Error().Err(modelErr).Str("component", "url_model").Msg(msg)
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize URL model")
		return
	}
	defer model.Close()

	srv := sharedhttp.NewDefaultServer()

	srv.Engine().Static("/static", "./static")
	srv.Engine().GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	srv.POST("/scan", scanHandler(model, tiChecker, log))

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
}

func scanHandler(model *urlpkg.URLModel, tiChecker *urlpkg.TIChecker, log zerolog.Logger) sharedhttp.HandlerFunc {
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

		var (
			mlScore int
			mlProb  float64
			routed  bool
			reason  string
			tiResult urlpkg.TIResult
			wg      sync.WaitGroup
		)

		wg.Add(2)

		go func() {
			defer wg.Done()
			mlScore, mlProb, routed, reason, _ = model.PredictWithRoute(ctx.Request().Context(), normalized)
		}()

		go func() {
			defer wg.Done()
			tiResult, _ = tiChecker.Check(ctx.Request().Context(), normalized)
		}()

		wg.Wait()

		label := classifyLabel(mlScore, tiResult, routed)
		degraded := mlScore == 50 && mlProb == 0.5

		log.Debug().
			Str("url", normalized).
			Int("ml_score", mlScore).
			Float64("ml_prob", mlProb).
			Bool("routed", routed).
			Str("route_reason", reason).
			Bool("ti_match", tiResult.Matched).
			Str("ti_threat", tiResult.ThreatType).
			Int("ti_risk", tiResult.RiskScore).
			Str("label", label).
			Bool("degraded", degraded).
			Msg("scan complete")

		_ = ctx.OK(scanResponse{
			URL:          normalized,
			Score:        mlScore,
			Probability:  mlProb,
			Label:        label,
			Routed:       routed,
			RouteReason:  reason,
			TIMatch:      tiResult.Matched,
			TIThreatType: tiResult.ThreatType,
			TIRiskScore:  tiResult.RiskScore,
			Degraded:     degraded,
		})
	}
}

func classifyLabel(mlScore int, ti urlpkg.TIResult, routed bool) string {
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
