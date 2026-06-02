package url

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/valkey"
)

type fakeDomainLookup struct {
	match valkey.DomainMatch
	err   error
}

func (f fakeDomainLookup) LookupDomain(_ context.Context, _ string) (valkey.DomainMatch, error) {
	return f.match, f.err
}

func TestTIChecker_SurfacesIndicatorID(t *testing.T) {
	t.Parallel()

	tc := NewTIChecker(fakeDomainLookup{match: valkey.DomainMatch{
		Matched:     true,
		IndicatorID: 4242,
		RiskScore:   90,
		ThreatType:  "phishing",
	}}, zerolog.Nop())

	res, err := tc.Check(context.Background(), "https://evil.example.com/login")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Matched || res.IndicatorID != 4242 || res.RiskScore != 90 || res.ThreatType != "phishing" {
		t.Fatalf("TIResult = %+v, want matched indicator 4242", res)
	}
	if res.Domain != "evil.example.com" {
		t.Errorf("Domain = %q, want evil.example.com", res.Domain)
	}
}

func TestTIChecker_LookupErrorDegradesToMiss(t *testing.T) {
	t.Parallel()

	tc := NewTIChecker(fakeDomainLookup{err: context.DeadlineExceeded}, zerolog.Nop())
	res, err := tc.Check(context.Background(), "https://example.com/")
	if err != nil {
		t.Fatalf("Check should swallow cache errors, got %v", err)
	}
	if res.Matched {
		t.Errorf("a cache error must degrade to not-matched, got %+v", res)
	}
}
