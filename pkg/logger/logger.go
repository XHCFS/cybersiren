package logger

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	once sync.Once
)

// initGlobalSettings standardises timestamp field name and format across all log lines.
// This is called once to avoid mutating global state on every New() call.
func initGlobalSettings() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "ts"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "msg"
}

// New creates a configured zerolog.Logger based on the provided options.
// The level is applied to the instance only, not globally.
func New(level string, pretty bool) zerolog.Logger {
	// Initialize global settings once (idempotent)
	once.Do(initGlobalSettings)

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	var logger zerolog.Logger

	if pretty {
		// Human-readable output for local development.
		// Never enable in production — it breaks log ingestion pipelines.
		logger = zerolog.New(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				TimeFormat: "15:04:05",
			},
		)
	} else {
		logger = zerolog.New(os.Stderr)
	}

	return logger.
		Level(lvl).
		With().
		Timestamp().
		Str("service", "cybersiren").
		Logger()
}

// SetGlobal assigns the logger as the zerolog global logger (log.Logger)
// and sets the global log level. After calling this, any library using
// zerolog's global will inherit the same configuration.
// This also ensures global field name settings are initialized.
//
// IMPORTANT: Call SetGlobal once during application startup, before
// spawning goroutines that read log.Logger. The write is not synchronised.
func SetGlobal(logger zerolog.Logger) {
	// Ensure global settings are initialized before setting global logger
	once.Do(initGlobalSettings)
	log.Logger = logger
}

// -- Convenience constructors for common pipeline scopes ----------------------
// These use zerolog's built-in context support (zerolog.Ctx) so they work
// with any third-party library that also uses zerolog's native context integration.

func loggerFromContext(ctx context.Context) *zerolog.Logger {
	l := zerolog.Ctx(ctx)
	if l.GetLevel() == zerolog.Disabled {
		// Fall back to the global logger if none is attached to the context.
		return &log.Logger
	}
	return l
}

// WithRequestID attaches a request_id field to the logger in ctx.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	l := loggerFromContext(ctx)
	return l.With().Str("request_id", requestID).Logger().WithContext(ctx)
}

// WithOrgID attaches an org_id field to the logger in ctx.
func WithOrgID(ctx context.Context, orgID int64) context.Context {
	l := loggerFromContext(ctx)
	return l.With().Int64("org_id", orgID).Logger().WithContext(ctx)
}

// WithEmailID attaches an email_id field to the logger in ctx.
func WithEmailID(ctx context.Context, emailID int64) context.Context {
	l := loggerFromContext(ctx)
	return l.With().Int64("email_id", emailID).Logger().WithContext(ctx)
}

// WithJobID attaches a job_id and job_type field to the logger in ctx.
func WithJobID(ctx context.Context, jobID int64, jobType string) context.Context {
	l := loggerFromContext(ctx)
	return l.With().
		Int64("job_id", jobID).
		Str("job_type", jobType).
		Logger().WithContext(ctx)
}

// WithThreatID attaches a threat_id field to the logger in ctx.
func WithThreatID(ctx context.Context, threatID int64) context.Context {
	l := loggerFromContext(ctx)
	return l.With().Int64("threat_id", threatID).Logger().WithContext(ctx)
}

// WithCampaignID attaches a campaign_id field to the logger in ctx.
func WithCampaignID(ctx context.Context, campaignID int64) context.Context {
	l := loggerFromContext(ctx)
	return l.With().Int64("campaign_id", campaignID).Logger().WithContext(ctx)
}
