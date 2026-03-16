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

func New(ctx context.Context, dsn string, log zerolog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}

	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

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

func MustNew(ctx context.Context, dsn string, log zerolog.Logger) *pgxpool.Pool {
	pool, err := New(ctx, dsn, log)
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
