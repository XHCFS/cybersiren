package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"syscall"
	"time"

	"os/signal"

	"github.com/rs/zerolog"
	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti/feeds"
	"github.com/saif/cybersiren/shared/config"
	httputil "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/logger"
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

	tracerShutdown, err := tracing.Init(ctx, "svc-11-ti-sync", cfg.JaegerEndpoint)
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

	reg := metrics.Init("svc-11-ti-sync")

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.HTTPHandler(reg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	metricsSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("metrics server error")
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = metricsSrv.Shutdown(shutdownCtx)
	}()

	poolOpts := pool.PoolOptions{
		MaxConns:          int32(cfg.DB.MaxConns),
		MinConns:          int32(cfg.DB.MinConns),
		MaxConnLifetime:   cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
	}
	pool := pool.MustNew(ctx, cfg.DB.DSN(), poolOpts, log)
	defer pool.Close()

	rdb := sharedvalkey.MustNew(sharedvalkey.ClientOptions{
		Addr:     cfg.Valkey.Addr,
		Password: cfg.Valkey.Password,
		DB:       cfg.Valkey.DB,
	}, log)
	defer rdb.Close()

	repo := repository.NewTIRepository(pool, log, reg)
	cache := sharedvalkey.NewTICache(rdb, repo, log, reg)

	enabledFeeds, err := db.New(pool).GetEnabledFeeds(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load enabled feeds")
		return
	}

	log.Info().Int("enabled_feed_rows", len(enabledFeeds)).Msg("discovered enabled feeds from db")
	warnFeedConfiguration(log, cfg, enabledFeeds)

	httpClient := httputil.NewClient()
	feedImpls := make([]ti.Feed, 0, len(enabledFeeds))

	for _, feedRow := range enabledFeeds {
		feedName := strings.ToLower(strings.TrimSpace(feedRow.Name))
		feedURL, ok := dbFeedURL(feedRow)
		if !ok {
			log.Warn().Str("feed", feedName).Int64("feed_id", feedRow.ID).Msg("feed has empty URL in db, skipping")
			continue
		}

		switch feedName {
		case "phishtank":
			feedImpl, feedErr := feeds.NewPhishTankFeed(feedRow.ID, cfg, httpClient, log)
			if feedErr != nil {
				if errors.Is(feedErr, ti.ErrPhishTankKeyMissing) {
					log.Warn().Msg("phishtank: no API key configured, skipping")
					continue
				}

				log.Error().Err(feedErr).Str("feed", feedName).Msg("failed to initialize feed")
				continue
			}

			feedImpl.URLTemplate = feedURL

			feedImpls = append(feedImpls, feedImpl)
		case "openphish":
			feedImpl := feeds.NewOpenPhishFeed(feedRow.ID, httpClient, log)
			feedImpl.URL = feedURL

			feedImpls = append(feedImpls, feedImpl)
		case "urlhaus":
			feedImpl := feeds.NewURLhausFeed(feedRow.ID, httpClient, log)
			feedImpl.URL = feedURL

			feedImpls = append(feedImpls, feedImpl)
		case "threatfox":
			feedImpl := feeds.NewThreatFoxFeed(feedRow.ID, cfg, httpClient, log)
			feedImpl.URL = feedURL

			feedImpls = append(feedImpls, feedImpl)
		case "malwarebazaar":
			feedImpl := feeds.NewMalwareBazaarFeed(feedRow.ID, cfg, httpClient, log)
			feedImpl.URL = feedURL

			feedImpls = append(feedImpls, feedImpl)
		default:
			log.Warn().Str("feed", feedRow.Name).Msg("unknown feed name in db, skipping")
		}
	}

	if len(feedImpls) == 0 {
		log.Fatal().Msg("no feeds enabled — check feeds table and config")
		return
	}

	for _, feedImpl := range feedImpls {
		log.Info().
			Str("feed", feedImpl.Name()).
			Int64("feed_id", feedImpl.FeedID()).
			Msg("feed enabled for sync")
	}

	runner := ti.NewRunner(feedImpls, repo, cache, log, reg)
	if err := runner.Start(ctx, time.Duration(cfg.SyncIntervalSeconds)*time.Second); err != nil {
		log.Fatal().Err(err).Msg("TI sync runner failed")
	}

	log.Info().Msg("shutdown complete")
}

func dbFeedURL(feedRow db.Feed) (string, bool) {
	if !feedRow.Url.Valid {
		return "", false
	}

	url := strings.TrimSpace(feedRow.Url.String)
	if url == "" {
		return "", false
	}

	return url, true
}

func warnFeedConfiguration(log zerolog.Logger, cfg *config.Config, enabledFeeds []db.Feed) {
	enabledByName := make(map[string]struct{}, len(enabledFeeds))
	for _, feed := range enabledFeeds {
		name := strings.ToLower(strings.TrimSpace(feed.Name))
		if name != "" {
			enabledByName[name] = struct{}{}
		}
	}

	if _, ok := enabledByName["phishtank"]; ok && strings.TrimSpace(cfg.FeedPhishTankAPIKey) == "" {
		log.Warn().Msg("phishtank is enabled in db but no API key is configured; feed will be skipped")
	}

	if _, ok := enabledByName["threatfox"]; ok && strings.TrimSpace(cfg.FeedThreatFoxAPIKey) == "" {
		log.Warn().Msg("threatfox is enabled in db but no API key is configured; upstream may return 401")
	}
}
