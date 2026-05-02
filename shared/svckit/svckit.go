// Package svckit is the common bootstrap used by every Infrastructure Spine v0
// pipeline stub. It is a thin convenience layer over shared/{config,logger,
// observability,kafka,postgres,valkey} — every step is something a stub would
// otherwise repeat verbatim in main().
//
// Stubs construct a Spec, call Run, and return. Run blocks on SIGINT/SIGTERM,
// pumps the consumer (if Inputs is non-empty), and tears resources down in
// reverse order on shutdown.
package svckit

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"
	valkeygo "github.com/valkey-io/valkey-go"

	"github.com/saif/cybersiren/shared/config"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/logger"
	"github.com/saif/cybersiren/shared/observability/metrics"
	"github.com/saif/cybersiren/shared/observability/tracing"
	"github.com/saif/cybersiren/shared/postgres/pool"
	sharedvalkey "github.com/saif/cybersiren/shared/valkey"
)

// Handler processes one Kafka record. The producer is shared with the
// service's main and may be nil if Spec.NeedsProducer is false.
type Handler func(ctx context.Context, rec *kgo.Record, p *kafkaproducer.Producer) error

// Spec describes one pipeline stub.
type Spec struct {
	Name string // "svc-04-header-analysis"

	// Inputs is the list of topics to consume; empty disables the consumer.
	Inputs []string
	// GroupID is the consumer group; required when Inputs is non-empty.
	GroupID string

	// NeedsProducer wires up a Kafka producer reachable inside Handler.
	NeedsProducer bool

	// NeedsDB causes Run to open a pool and Ping it. Healthcheck only — no
	// queries are issued by Run itself. Per spine v0 scope, stubs do not
	// touch business tables.
	NeedsDB bool

	// NeedsValkey opens a Valkey client. Required by svc-07-aggregator only;
	// for everyone else this stays false.
	NeedsValkey bool

	// Handler runs on every consumed record. Ignored when Inputs is empty.
	Handler Handler

	// HTTPRoutes is a hook for stubs that need an HTTP endpoint (svc-01
	// /ingest, svc-10 dashboard scaffolding). The mux is bound on HTTPPort.
	HTTPRoutes func(mux *http.ServeMux, deps Deps)
	HTTPPort   int

	// OnReady runs after all clients are wired but before the consumer pump
	// starts. Stubs use it for one-shot startup work.
	OnReady func(ctx context.Context, deps Deps) error
}

// Deps is the bag of resources that long-lived stub callbacks (HTTPRoutes,
// OnReady) need access to. Fields are nil when the corresponding NeedsXxx
// flag was false.
type Deps struct {
	Cfg      *config.Config
	Log      zerolog.Logger
	Producer *kafkaproducer.Producer
	Pool     *pgxpool.Pool
	Valkey   valkeygo.Client
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

	deps := Deps{Cfg: cfg, Log: log}

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

	if spec.NeedsProducer {
		prod, err := kafkaproducer.New(kafkaproducer.Config{
			Brokers:  cfg.Kafka.Brokers,
			ClientID: clientIDFor(cfg.Kafka.ClientID, spec.Name),
			Service:  spec.Name,
		}, reg, log)
		if err != nil {
			return fmt.Errorf("kafka producer: %w", err)
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = prod.Close(shutdownCtx)
		}()
		deps.Producer = prod
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

	if len(spec.Inputs) > 0 {
		if spec.Handler == nil {
			return fmt.Errorf("svckit: Handler required when Inputs is set")
		}
		if spec.GroupID == "" {
			return fmt.Errorf("svckit: GroupID required when Inputs is set")
		}
		cons, err := kafkaconsumer.New(kafkaconsumer.Config{
			Brokers:  cfg.Kafka.Brokers,
			ClientID: clientIDFor(cfg.Kafka.ClientID, spec.Name),
			GroupID:  groupIDFor(cfg.Kafka.ConsumerGroupPrefix, spec.GroupID),
			Topics:   spec.Inputs,
			Service:  spec.Name,
		}, reg, log)
		if err != nil {
			return fmt.Errorf("kafka consumer: %w", err)
		}
		defer cons.Close()

		log.Info().Strs("inputs", spec.Inputs).Str("group", spec.GroupID).Msg("starting consumer")
		err = cons.Run(ctx, func(ctx context.Context, rec *kgo.Record) error {
			return spec.Handler(ctx, rec, deps.Producer)
		})
		if err != nil {
			return err
		}
	} else {
		log.Info().Msg("no Kafka inputs; idling until signal")
		<-ctx.Done()
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

func groupIDFor(prefix, group string) string {
	if prefix == "" {
		return group
	}
	return prefix + "." + group
}
