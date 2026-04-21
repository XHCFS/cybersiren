package main

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	nlppkg "github.com/saif/cybersiren/services/svc-06-nlp/internal/nlp"
	"github.com/saif/cybersiren/shared/config"
	sharedhttp "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
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

	tracerShutdown, err := tracing.Init(ctx, "svc-06-nlp", cfg.JaegerEndpoint)
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

	reg := metrics.Init("svc-06-nlp")

	metricsShutdown, err := metrics.StartServer(cfg.MetricsPort, reg, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start metrics server")
		return
	}
	defer func() { _ = metricsShutdown(context.Background()) }()

	nlpClient := nlppkg.NewClient(cfg.ML.NLPServiceURL, reg, log)

	srv := sharedhttp.NewDefaultServer()

	// DEMO ONLY: static demo UI — not a production feature.
	srv.Engine().Static("/static", "./static")
	srv.Engine().GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	srv.POST("/predict", predictHandler(nlpClient, log))
	srv.GET("/healthz", healthHandler(nlpClient, log))
	srv.GET("/status", statusHandler(nlpClient, log))

	go func() {
		if srvErr := srv.Start(fmt.Sprintf(":%d", cfg.Server.Port)); srvErr != nil {
			log.Error().Err(srvErr).Msg("http server error")
		}
	}()

	log.Info().
		Int("port", cfg.Server.Port).
		Int("metrics_port", cfg.MetricsPort).
		Str("nlp_backend", cfg.ML.NLPServiceURL).
		Msg("svc-06-nlp started")

	<-ctx.Done()
	log.Info().Msg("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Error().Err(shutdownErr).Msg("http server shutdown error")
	}

	log.Info().Msg("shutdown complete")
}

// predictHandler proxies POST /predict to the Python NLP inference service.
// DEMO ONLY: drives the interactive email scanning demo page.
func predictHandler(client *nlppkg.Client, log zerolog.Logger) sharedhttp.HandlerFunc {
	return func(ctx sharedhttp.Context) {
		var req nlppkg.PredictRequest
		if reqErr := ctx.ParseJSON(&req); reqErr != nil {
			_ = ctx.RequestError(reqErr)
			return
		}
		if req.Subject == "" && req.BodyPlain == "" {
			_ = ctx.Error(http.StatusBadRequest, "bad_request", "subject or body_plain is required")
			return
		}

		resp, upstreamStatus, err := client.Predict(ctx.Request().Context(), req)
		if err != nil {
			log.Error().Err(err).Msg("nlp predict failed")
			status := http.StatusBadGateway
			if upstreamStatus > 0 {
				status = upstreamStatus
			}
			_ = ctx.Error(status, "nlp_error", err.Error())
			return
		}

		log.Debug().
			Str("classification", resp.Classification).
			Float64("confidence", resp.Confidence).
			Int("content_risk_score", resp.ContentRiskScore).
			Bool("obfuscation_detected", resp.ObfuscationDetected).
			Msg("nlp predict complete")

		_ = ctx.OK(resp)
	}
}

// healthHandler proxies GET /healthz to the Python NLP inference service.
func healthHandler(client *nlppkg.Client, log zerolog.Logger) sharedhttp.HandlerFunc {
	return func(ctx sharedhttp.Context) {
		ready, err := client.Health(ctx.Request().Context())
		if err != nil || !ready {
			log.Warn().Err(err).Msg("nlp health check failed")
			_ = ctx.Error(http.StatusServiceUnavailable, "nlp_unavailable", "NLP model is not loaded")
			return
		}
		_ = ctx.OK(map[string]any{"status": "ok", "model_ready": true})
	}
}

// statusHandler proxies GET /status to the Python NLP inference service.
// Always returns 200 — used by the demo UI to show model loading progress.
// DEMO ONLY: not a production endpoint.
func statusHandler(client *nlppkg.Client, log zerolog.Logger) sharedhttp.HandlerFunc {
	return func(ctx sharedhttp.Context) {
		resp, err := client.Status(ctx.Request().Context())
		if err != nil {
			log.Warn().Err(err).Msg("nlp status check failed")
			_ = ctx.OK(map[string]any{
				"model_ready":          false,
				"loading_stage":        "starting",
				"loading_progress_pct": 0,
			})
			return
		}
		_ = ctx.OK(resp)
	}
}
