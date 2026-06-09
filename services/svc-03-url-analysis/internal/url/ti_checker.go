package url

import (
	"context"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/valkey"
)

var tiCheckerTracer = otel.Tracer("svc-03-url-analysis/ti-checker")

// TIResult holds the outcome of a threat-intelligence cache lookup.
type TIResult struct {
	Matched    bool
	Domain     string
	RiskScore  int
	ThreatType string
	// IndicatorID is the matched ti_indicators.id, surfaced so the persistence
	// layer can write the email_url_ti_matches audit row. Zero when the cache
	// entry predates the id being stored (a legacy entry); the audit then skips.
	IndicatorID int64
}

// TIChecker performs threat-intelligence lookups against the Valkey domain cache.
type TIChecker struct {
	cache valkey.TICache
	log   zerolog.Logger
}

// NewTIChecker returns a TIChecker backed by the given cache.
func NewTIChecker(cache valkey.TICache, log zerolog.Logger) *TIChecker {
	return &TIChecker{cache: cache, log: log}
}

// Check looks up the domain extracted from rawURL in the TI cache.
func (tc *TIChecker) Check(ctx context.Context, rawURL string) (TIResult, error) {
	ctx, span := tiCheckerTracer.Start(ctx, "TIChecker.Check")
	defer span.End()

	domain, err := normalization.ExtractDomain(rawURL)
	if err != nil {
		tc.log.Warn().Err(err).Str("url", rawURL).Msg("failed to extract domain for TI check")
		return TIResult{}, nil // graceful degradation
	}

	lookup, err := tc.cache.LookupDomain(ctx, domain)
	if err != nil {
		tc.log.Warn().Err(err).Str("domain", domain).Msg("TI cache lookup failed")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return TIResult{}, nil // cache miss = not blocked
	}

	return TIResult{
		Matched:     lookup.Blocked,
		Domain:      domain,
		RiskScore:   lookup.RiskScore,
		ThreatType:  lookup.ThreatType,
		IndicatorID: lookup.IndicatorID,
	}, nil
}
