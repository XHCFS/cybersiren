// Package main is the entrypoint for SVC-04 Header Analysis Service.
//
// Pipeline:
//
//	consume analysis.headers (Kafka)
//	  → load active header/email rules (Postgres + Valkey rules_cache)
//	  → extract Auth / Reputation / Structural signals
//	  → run JSON DSL evaluator → list of fired rules
//	  → INSERT rule_hits (atomic transaction; retry with backoff)
//	  → publish scores.header (Kafka)
//	  → commit offset (only after rule_hits commit succeeds)
//
// See docs/architecture/architecture-spec-detail.html §1 step 3b.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/processor"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	svcti "github.com/saif/cybersiren/services/svc-04-header-analysis/internal/ti"
	"github.com/saif/cybersiren/shared/config"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	sharedproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

const serviceName = "svc-04-header-analysis"

func main() {
	if err := run(); err != nil {
		// run() always logs before returning; this is a last-ditch
		// surface so wrapping stacks see the exit code.
		fmt.Fprintf(os.Stderr, "%s exited with error: %v\n", serviceName, err)
		os.Exit(1)
	}
}

func run() error {
	bootstrapLog := logger.New("info", true)

	cfg, err := config.Load()
	if err != nil {
		bootstrapLog.Error().Err(err).Msg("failed to load config")
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid config")
		return fmt.Errorf("validate config: %w", err)
	}
	if err := cfg.Header.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid header config")
		return fmt.Errorf("validate header config: %w", err)
	}
	if err := cfg.Kafka.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid kafka config")
		return fmt.Errorf("validate kafka config: %w", err)
	}

	log := logger.New(cfg.Log.Level, cfg.Log.Pretty)
	logger.SetGlobal(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tracerShutdown, err := tracing.Init(ctx, serviceName, cfg.JaegerEndpoint)
	if err != nil {
		log.Error().Err(err).Msg("failed to initialize tracing")
		return fmt.Errorf("init tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := tracerShutdown(shutdownCtx); shutdownErr != nil {
			log.Error().Err(shutdownErr).Msg("tracer shutdown error")
		}
	}()

	reg := metrics.Init(serviceName)
	valkeyHealthy := registerValkeyHealthGauge(reg)
	metricsShutdown, err := metrics.StartServer(cfg.MetricsPort, reg, log)
	if err != nil {
		log.Error().Err(err).Msg("failed to start metrics server")
		return fmt.Errorf("start metrics server: %w", err)
	}
	defer func() { _ = metricsShutdown(context.Background()) }()

	dbPool := pool.MustNew(ctx, cfg.DB.DSN(), pool.PoolOptions{
		MaxConns:          int32(cfg.DB.MaxConns),
		MinConns:          int32(cfg.DB.MinConns),
		MaxConnLifetime:   cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
	}, log)
	defer dbPool.Close()

	valkeyClient, valkeyErr := sharedvalkey.New(sharedvalkey.ClientOptions{
		Addr:     cfg.Valkey.Addr,
		Password: cfg.Valkey.Password,
		DB:       cfg.Valkey.DB,
	}, log)
	if valkeyErr != nil {
		valkeyHealthy.Set(0)
		log.Warn().Err(valkeyErr).Msg("Valkey unavailable at startup; continuing with Postgres-backed TI and rules lookup")
	} else {
		valkeyHealthy.Set(1)
		defer valkeyClient.Close()
	}

	rulesCache := rules.NewCache(dbPool, valkeyClient, rules.CacheConfig{
		Targets: []string{"header", "email"},
		TTL:     time.Duration(cfg.Header.RuleCacheTTLSeconds) * time.Second,
	}, log, reg)

	// Warm up cache for "global" org (org_id=0 means "match global rules
	// only" given our SQL filter (org_id=? OR org_id IS NULL)). Per-org
	// entries are loaded lazily on first message.
	if _, warmErr := rulesCache.Get(ctx, 0); warmErr != nil {
		log.Warn().Err(warmErr).Msg("initial rules cache load failed (will retry on first message)")
	}

	go rulesCache.StartRefreshLoop(ctx)

	producer, err := sharedproducer.New(sharedproducer.Config{
		Brokers:  cfg.Kafka.Brokers,
		Topic:    cfg.Header.ProduceTopic,
		ClientID: cfg.Kafka.ClientID,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka producer")
		return fmt.Errorf("build kafka producer: %w", err)
	}
	defer func() { _ = producer.Close() }()

	consumer, err := sharedconsumer.New(sharedconsumer.Config{
		Brokers: cfg.Kafka.Brokers,
		Topic:   cfg.Header.ConsumeTopic,
		GroupID: cfg.Header.ConsumerGroup,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka consumer")
		return fmt.Errorf("build kafka consumer: %w", err)
	}
	defer func() { _ = consumer.Close() }()

	procMetrics := processor.NewMetrics(reg)
	tiLookup := svcti.NewFallbackLookup(valkeyClient, svcti.NewPostgresIndicatorLookup(dbPool), log)
	reputationExtractor := header.NewReputationExtractorWithObserver(
		tiLookup,
		cfg.Header.TyposquatMaxDistance,
		log,
		func() { procMetrics.ErrorsTotal.WithLabelValues("ti_lookup").Inc() },
	)

	writer := processor.NewRuleHitWriter(dbPool, cfg.Header.DBWriteRetryAttempts, log)

	proc := processor.New(processor.Config{
		HopCountThreshold:       cfg.Header.HopCountThreshold,
		TimeDriftHoursThreshold: cfg.Header.TimeDriftHoursThreshold,
		TyposquatMaxDistance:    cfg.Header.TyposquatMaxDistance,
		ScoringBlend:            cfg.Header.ScoringBlend,
		AuthWeight:              cfg.Header.AuthWeight,
		ReputationWeight:        cfg.Header.ReputationWeight,
		StructuralWeight:        cfg.Header.StructuralWeight,
		PublishRetryAttempts:    cfg.Header.PublishRetryAttempts,
	}, rulesCache, reputationExtractor, writer, producer, procMetrics, log)

	log.Info().
		Str("service", serviceName).
		Str("consume_topic", cfg.Header.ConsumeTopic).
		Str("produce_topic", cfg.Header.ProduceTopic).
		Str("consumer_group", cfg.Header.ConsumerGroup).
		Str("kafka_brokers", cfg.Kafka.Brokers).
		Int("metrics_port", cfg.MetricsPort).
		Msg("svc-04-header-analysis started")

	if runErr := consumer.Run(ctx, proc.Handle); runErr != nil && !errors.Is(runErr, context.Canceled) {
		log.Error().Err(runErr).Msg("kafka consumer loop ended with error")
		return fmt.Errorf("consumer run: %w", runErr)
	}

	log.Info().Msg("shutdown complete")
	return nil
}

func registerValkeyHealthGauge(reg *prometheus.Registry) prometheus.Gauge {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "header_analysis_valkey_healthy",
		Help: "Whether SVC-04 connected to Valkey at startup (1 healthy, 0 degraded).",
	})
	if err := reg.Register(gauge); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
		}
	}
	return gauge
}
