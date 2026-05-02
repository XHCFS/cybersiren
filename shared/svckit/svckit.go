// Package svckit is the common bootstrap used by every Infrastructure Spine v0
// pipeline stub. It is a thin convenience layer over shared/{config,logger,
// observability,kafka,postgres,valkey}. Each step is something a stub would
// otherwise repeat verbatim in main().
//
// Each Producer and Consumer is single-topic-per-instance (matching the
// shared/kafka API used by real services like svc-04). Stubs that fan out
// to multiple topics (svc-02) declare every output topic; stubs that fan
// in from multiple topics (svc-07) declare every input topic — svckit
// spawns one Producer / Consumer per topic.
//
// Stubs construct a Spec, call Run, and return. Run blocks on SIGINT/SIGTERM,
// pumps the consumers, and tears resources down in reverse order on shutdown.
package svckit

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/sync/errgroup"

	"github.com/saif/cybersiren/shared/config"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

// Handler processes one Kafka message. The deps argument exposes shared
// resources (producers keyed by topic, optional Postgres pool, optional
// Valkey client). Return non-nil to skip committing the offset.
type Handler func(ctx context.Context, msg kafkaconsumer.Message, deps Deps) error

// Spec describes one pipeline stub.
type Spec struct {
	Name string // "svc-04-header-analysis"

	// ConsumerTopics is the list of topics to consume; each gets a
	// consumer in the same GroupID. Empty disables consumption.
	ConsumerTopics []string
	// GroupID is the consumer group; required when ConsumerTopics is non-empty.
	GroupID string

	// ProducerTopics is the list of topics this stub publishes to. For
	// each one a Producer is created and accessible from Handler via
	// Deps.Producers keyed by topic name.
	ProducerTopics []string

	// NeedsDB causes Run to open a pool and Ping it. Healthcheck only —
	// no queries are issued by Run itself.
	NeedsDB bool

	// NeedsValkey opens a Valkey client.
	NeedsValkey bool

	// Handler runs on every consumed record. Ignored when ConsumerTopics
	// is empty.
	Handler Handler

	// HTTPRoutes is a hook for stubs that need an HTTP endpoint (svc-01
	// /ingest, svc-10 dashboard scaffolding). The mux is bound on HTTPPort.
	HTTPRoutes func(mux *http.ServeMux, deps Deps)
	HTTPPort   int

	// OnReady runs after all clients are wired but before the consumer
	// loop starts. Stubs use it for one-shot startup work.
	OnReady func(ctx context.Context, deps Deps) error
}

// Deps is the bag of resources passed to handlers, HTTP routes, and OnReady.
type Deps struct {
	Cfg       *config.Config
	Log       zerolog.Logger
	Registry  *prometheus.Registry
	Pool      *pgxpool.Pool
	Valkey    valkeygo.Client
	Producers map[string]*kafkaproducer.Producer
}

// Run wires up the stub and blocks until SIGINT/SIGTERM. Returns nil on
// graceful shutdown, error on bootstrap failure.
func Run(spec Spec) error {
	if spec.Name == "" {
		return fmt.Errorf("svckit: spec.Name required")
	}

	bootstrapLog := logger.New("info", true).With().Str("svc", spec.Name).Logger()

	cfg, err := config.Load()
	if err != nil {
		bootstrapLog.Error().Err(err).Msg("config load failed")
		return err
	}
	if err := cfg.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("config invalid")
		return err
	}
	if err := cfg.Kafka.Validate(); err != nil {
		bootstrapLog.Error().Err(err).Msg("kafka config invalid")
		return err
	}

	log := logger.New(cfg.Log.Level, cfg.Log.Pretty).With().Str("svc", spec.Name).Logger()
	logger.SetGlobal(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tracerShutdown, err := tracing.Init(ctx, spec.Name, cfg.JaegerEndpoint)
	if err != nil {
		return fmt.Errorf("tracing init: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracerShutdown(shutdownCtx)
	}()

	reg := metrics.Init(spec.Name)
	metricsShutdown, err := metrics.StartServer(cfg.MetricsPort, reg, log)
	if err != nil {
		return fmt.Errorf("metrics server: %w", err)
	}
	defer func() { _ = metricsShutdown(context.Background()) }()

	deps := Deps{Cfg: cfg, Log: log, Registry: reg, Producers: map[string]*kafkaproducer.Producer{}}

	if spec.NeedsDB {
		opts := pool.PoolOptions{
			MaxConns:          int32(cfg.DB.MaxConns),
			MinConns:          int32(cfg.DB.MinConns),
			MaxConnLifetime:   cfg.DB.MaxConnLifetime,
			MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
			HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
		}
		p, err := pool.New(ctx, cfg.DB.DSN(), opts, log)
		if err != nil {
			return fmt.Errorf("postgres pool: %w", err)
		}
		defer p.Close()
		deps.Pool = p
	}

	if spec.NeedsValkey {
		v, err := sharedvalkey.New(sharedvalkey.ClientOptions{
			Addr:     cfg.Valkey.Addr,
			Password: cfg.Valkey.Password,
			DB:       cfg.Valkey.DB,
		}, log)
		if err != nil {
			return fmt.Errorf("valkey: %w", err)
		}
		defer v.Close()
		deps.Valkey = v
	}

	for _, topic := range spec.ProducerTopics {
		prod, err := kafkaproducer.New(kafkaproducer.Config{
			Brokers:  cfg.Kafka.Brokers,
			Topic:    topic,
			ClientID: clientIDFor(cfg.Kafka.ClientID, spec.Name),
		}, log, reg)
		if err != nil {
			return fmt.Errorf("kafka producer for %s: %w", topic, err)
		}
		topic := topic
		defer func() { _ = prod.Close() }()
		deps.Producers[topic] = prod
	}

	if spec.HTTPRoutes != nil {
		mux := http.NewServeMux()
		spec.HTTPRoutes(mux, deps)
		port := spec.HTTPPort
		if port == 0 {
			port = cfg.Server.Port
		}
		srv := &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info().Int("port", port).Msg("http server listening")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("http server error")
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
	}

	if spec.OnReady != nil {
		if err := spec.OnReady(ctx, deps); err != nil {
			return fmt.Errorf("on-ready: %w", err)
		}
	}

	if len(spec.ConsumerTopics) == 0 {
		log.Info().Msg("no Kafka inputs; idling until signal")
		<-ctx.Done()
		log.Info().Msg("shutdown complete")
		return nil
	}

	if spec.Handler == nil {
		return fmt.Errorf("svckit: Handler required when ConsumerTopics is set")
	}
	if spec.GroupID == "" {
		return fmt.Errorf("svckit: GroupID required when ConsumerTopics is set")
	}

	consumers := make([]*kafkaconsumer.Consumer, 0, len(spec.ConsumerTopics))
	for _, topic := range spec.ConsumerTopics {
		c, err := kafkaconsumer.New(kafkaconsumer.Config{
			Brokers:  cfg.Kafka.Brokers,
			Topic:    topic,
			GroupID:  spec.GroupID,
			ClientID: clientIDFor(cfg.Kafka.ClientID, spec.Name),
		}, log, reg)
		if err != nil {
			return fmt.Errorf("kafka consumer for %s: %w", topic, err)
		}
		consumers = append(consumers, c)
	}
	defer func() {
		for _, c := range consumers {
			_ = c.Close()
		}
	}()

	log.Info().Strs("inputs", spec.ConsumerTopics).Str("group", spec.GroupID).Msg("starting consumers")

	g, gctx := errgroup.WithContext(ctx)
	var once sync.Once
	for _, c := range consumers {
		c := c
		g.Go(func() error {
			err := c.Run(gctx, func(ctx context.Context, msg kafkaconsumer.Message) error {
				return spec.Handler(ctx, msg, deps)
			})
			if err != nil {
				once.Do(func() { log.Error().Err(err).Msg("consumer loop ended with error") })
			}
			return err
		})
	}
	if err := g.Wait(); err != nil && err != context.Canceled {
		return err
	}

	log.Info().Msg("shutdown complete")
	return nil
}

func clientIDFor(prefix, svcName string) string {
	if prefix == "" {
		return svcName
	}
	return prefix + "-" + svcName
}
