// Package main is the entrypoint for SVC-05 Attachment Analysis Service.
//
// Pipeline:
//
//	consume analysis.attachments (Kafka)
//	  → per attachment: hash lookup (attachment_library.sha256 → is_malicious)
//	  → VirusTotal (24h enrichment_results cache; 429 fail-open; no key ⇒ skip)
//	  → 5 heuristics (entropy>7.5, ext/MIME mismatch, dangerous ext, macro
//	    Office, double-extension)
//	  → take the per-email MAX across attachments
//	  → WRITE attachment_library (malware flag) + UPDATE email_attachments.risk_score
//	  → publish scores.attachment (Kafka)
//	  → commit offset (only after the DB writes succeed)
//
// See docs/architecture/architecture-spec-detail.html §1 step 3c + §15 gap #2.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/processor"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/scoring"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/store"
	"github.com/saif/cybersiren/services/svc-05-attachment-analysis/internal/vt"
	"github.com/saif/cybersiren/shared/config"
	sharedconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	sharedproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
)

const serviceName = "svc-05-attachment-analysis"

func main() {
	if err := run(); err != nil {
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
	if err := cfg.Attachment.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("invalid attachment config")
		return fmt.Errorf("validate attachment config: %w", err)
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

	producer, err := sharedproducer.New(sharedproducer.Config{
		Brokers:  cfg.Kafka.Brokers,
		Topic:    cfg.Attachment.ProduceTopic,
		ClientID: cfg.Kafka.ClientID,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka producer")
		return fmt.Errorf("build kafka producer: %w", err)
	}
	defer func() { _ = producer.Close() }()

	consumer, err := sharedconsumer.New(sharedconsumer.Config{
		Brokers: cfg.Kafka.Brokers,
		Topic:   cfg.Attachment.ConsumeTopic,
		GroupID: cfg.Attachment.ConsumerGroup,
	}, log, reg)
	if err != nil {
		log.Error().Err(err).Msg("failed to build kafka consumer")
		return fmt.Errorf("build kafka consumer: %w", err)
	}
	defer func() { _ = consumer.Close() }()

	// VirusTotal credential + HTTP client come from Enrichment.VirusTotal (the
	// single source of truth for the VT key); the cache TTL + heuristic weights
	// come from the Attachment section. An empty key ⇒ the client skips VT and
	// never errors (ARCH-SPEC §1 step 3c).
	vtClient := vt.New(
		cfg.Enrichment.VirusTotal.APIKey,
		cfg.Enrichment.VirusTotal.BaseURL,
		cfg.Enrichment.VirusTotal.Timeout,
	)

	procMetrics := processor.NewMetrics(reg)
	repoStore := store.NewRepoStore(dbPool)

	proc := processor.New(processor.Config{
		Scoring: scoring.Config{
			EntropyThreshold:       cfg.Attachment.EntropyThreshold,
			HighEntropyScore:       cfg.Attachment.HighEntropyScore,
			ExtensionMismatchScore: cfg.Attachment.ExtensionMismatchScore,
			DangerousExtScore:      cfg.Attachment.DangerousExtScore,
			MacroOfficeScore:       cfg.Attachment.MacroOfficeScore,
			DoubleExtScore:         cfg.Attachment.DoubleExtScore,
			MaliciousHashScore:     cfg.Attachment.MaliciousHashScore,
		},
		VTCacheTTL:           cfg.Attachment.VTCacheTTL,
		PublishRetryAttempts: 5,
	}, repoStore, vtClient, producer, procMetrics, log)

	log.Info().
		Str("service", serviceName).
		Str("consume_topic", cfg.Attachment.ConsumeTopic).
		Str("produce_topic", cfg.Attachment.ProduceTopic).
		Str("consumer_group", cfg.Attachment.ConsumerGroup).
		Str("kafka_brokers", cfg.Kafka.Brokers).
		Bool("virustotal_enabled", vtClient.Enabled()).
		Int("metrics_port", cfg.MetricsPort).
		Msg("svc-05-attachment-analysis started")

	if runErr := consumer.Run(ctx, proc.Handle); runErr != nil && !errors.Is(runErr, context.Canceled) {
		log.Error().Err(runErr).Msg("kafka consumer loop ended with error")
		return fmt.Errorf("consumer run: %w", runErr)
	}

	log.Info().Msg("shutdown complete")
	return nil
}
