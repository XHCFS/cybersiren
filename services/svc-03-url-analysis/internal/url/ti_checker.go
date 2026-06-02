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

// DomainLookup is the slice of the TI cache the checker needs: a domain lookup
// that returns the matched indicator id. *valkey.ValkeyTICache satisfies it.
type DomainLookup interface {
	LookupDomain(ctx context.Context, domain string) (valkey.DomainMatch, error)
}

// TIResult holds the outcome of a threat-intelligence cache lookup.
type TIResult struct {
	Matched     bool
	Domain      string
	IndicatorID int64
	RiskScore   int
	ThreatType  string
}

// TIChecker performs threat-intelligence lookups against the Valkey domain cache.
type TIChecker struct {
	cache DomainLookup
	log   zerolog.Logger
}

// NewTIChecker returns a TIChecker backed by the given cache.
func NewTIChecker(cache DomainLookup, log zerolog.Logger) *TIChecker {
	return &TIChecker{cache: cache, log: log}
}

// Check looks up the domain extracted from rawURL in the TI cache, returning the
// matched ti_indicator_id so callers can record an email_url_ti_matches row.
func (tc *TIChecker) Check(ctx context.Context, rawURL string) (TIResult, error) {
	ctx, span := tiCheckerTracer.Start(ctx, "TIChecker.Check")
	defer span.End()

	domain, err := normalization.ExtractDomain(rawURL)
	if err != nil {
		tc.log.Warn().Err(err).Str("url", rawURL).Msg("failed to extract domain for TI check")
		return TIResult{}, nil // graceful degradation
	}

	match, err := tc.cache.LookupDomain(ctx, domain)
	if err != nil {
		tc.log.Warn().Err(err).Str("domain", domain).Msg("TI cache lookup failed")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return TIResult{}, nil // cache miss = not blocked
	}

	return TIResult{
		Matched:     match.Matched,
		Domain:      domain,
		IndicatorID: match.IndicatorID,
		RiskScore:   match.RiskScore,
		ThreatType:  match.ThreatType,
	}, nil
}
