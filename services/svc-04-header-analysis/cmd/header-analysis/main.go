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

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/processor"
	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/rules"
	"github.com/saif/cybersiren/shared/config"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	sharedproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
	"github.com/saif/cybersiren/shared/postgres/repository"
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
		return err
	}
	if err := cfg.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid config")
		return err
	}
	if err := cfg.Header.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid header config")
		return err
	}
	if err := cfg.Kafka.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid kafka config")
		return err
	}

	log := logger.New(cfg.Log.Level, cfg.Log.Pretty)
	logger.SetGlobal(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tracerShutdown, err := tracing.Init(ctx, serviceName, cfg.JaegerEndpoint)
	if err != nil {
		log.Error().Err(err).Msg("failed to initialize tracing")
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := tracerShutdown(shutdownCtx); shutdownErr != nil {
			log.Error().Err(shutdownErr).Msg("tracer shutdown error")
		}
	}()

	reg := metrics.Init(serviceName)
	metricsShutdown, err := metrics.StartServer(cfg.MetricsPort, reg, log)
	if err != nil {
		log.Error().Err(err).Msg("failed to start metrics server")
		return err
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

	valkeyClient := sharedvalkey.MustNew(sharedvalkey.ClientOptions{
		Addr:     cfg.Valkey.Addr,
		Password: cfg.Valkey.Password,
		DB:       cfg.Valkey.DB,
	}, log)
	defer valkeyClient.Close()

	tiRepo := repository.NewTIRepository(dbPool, log, reg)
	tiCache := sharedvalkey.NewTICache(valkeyClient, tiRepo, log, reg, int64(cfg.TIHashCacheTTLSeconds))

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

	reputationExtractor := header.NewReputationExtractor(tiCache, cfg.Header.TyposquatMaxDistance, log)

	producer, err := sharedproducer.New(sharedproducer.Config{
		Brokers:  cfg.Kafka.Brokers,
		Topic:    cfg.Header.ProduceTopic,
		ClientID: cfg.Kafka.ClientID,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka producer")
		return err
	}
	defer func() { _ = producer.Close() }()

	consumer, err := sharedconsumer.New(sharedconsumer.Config{
		Brokers: cfg.Kafka.Brokers,
		Topic:   cfg.Header.ConsumeTopic,
		GroupID: cfg.Header.ConsumerGroup,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka consumer")
		return err
	}
	defer func() { _ = consumer.Close() }()

	procMetrics := processor.NewMetrics(reg)

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
		return runErr
	}

	log.Info().Msg("shutdown complete")
	return nil
}
