package pool

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/observability/tracing"
)

// PoolOptions holds configurable pgxpool tuning parameters.
// Zero values fall back to sensible defaults.
type PoolOptions struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

func (o PoolOptions) withDefaults() PoolOptions {
	if o.MaxConns <= 0 {
		o.MaxConns = 10
	}
	if o.MinConns <= 0 {
		o.MinConns = 2
	}
	if o.MaxConnLifetime <= 0 {
		o.MaxConnLifetime = time.Hour
	}
	if o.MaxConnIdleTime <= 0 {
		o.MaxConnIdleTime = 30 * time.Minute
	}
	if o.HealthCheckPeriod <= 0 {
		o.HealthCheckPeriod = 30 * time.Second
	}
	return o
}

func New(ctx context.Context, dsn string, opts PoolOptions, log zerolog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}

	o := opts.withDefaults()
	cfg.MaxConns = o.MaxConns
	cfg.MinConns = o.MinConns
	cfg.MaxConnLifetime = o.MaxConnLifetime
	cfg.MaxConnIdleTime = o.MaxConnIdleTime
	cfg.HealthCheckPeriod = o.HealthCheckPeriod

	_ = tracing.Tracer("shared/postgres/pool")
	cfg.ConnConfig.Tracer = otelpgx.NewTracer()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := otelpgx.RecordStats(pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("record postgres stats: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	log.Info().
		Str("db_host", dsnHost(dsn)).
		Msg("connected to postgres")

	return pool, nil
}

func MustNew(ctx context.Context, dsn string, opts PoolOptions, log zerolog.Logger) *pgxpool.Pool {
	pool, err := New(ctx, dsn, opts, log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize postgres pool")
		return nil
	}

	return pool
}

func dsnHost(dsn string) string {
	u, err := url.Parse(dsn)
	if err == nil {
		host := strings.TrimSpace(u.Hostname())
		if host != "" {
			return host
		}
	}

	for _, token := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "host") {
			host := strings.Trim(strings.TrimSpace(value), "'")
			if host != "" {
				return host
			}
		}
	}

	return "unknown"
}
