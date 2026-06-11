package url

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/valkey"
)

// fakeTICache is a valkey.TICache stub: only LookupDomain is exercised by the
// TI checker; the refresh methods and IsBlocklisted are present to satisfy the
// interface.
type fakeTICache struct {
	lookup valkey.DomainLookup
	err    error
}

func (f *fakeTICache) RefreshDomainCache(_ context.Context) error { return nil }

func (f *fakeTICache) IsBlocklisted(_ context.Context, _ string) (bool, int, string, error) {
	return f.lookup.Blocked, f.lookup.RiskScore, f.lookup.ThreatType, f.err
}

func (f *fakeTICache) LookupDomain(_ context.Context, _ string) (valkey.DomainLookup, error) {
	if f.err != nil {
		return valkey.DomainLookup{}, f.err
	}
	return f.lookup, nil
}

func TestTIChecker_Check_PropagatesIndicatorID(t *testing.T) {
	t.Parallel()

	cache := &fakeTICache{lookup: valkey.DomainLookup{
		Blocked:     true,
		RiskScore:   90,
		ThreatType:  "phishing",
		IndicatorID: 4242,
	}}
	checker := NewTIChecker(cache, zerolog.Nop())

	got, err := checker.Check(context.Background(), "https://evil.example/login")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !got.Matched {
		t.Fatalf("expected Matched=true, got %+v", got)
	}
	if got.IndicatorID != 4242 {
		t.Errorf("IndicatorID not propagated: want 4242, got %d", got.IndicatorID)
	}
	if got.RiskScore != 90 || got.ThreatType != "phishing" {
		t.Errorf("risk/threat not propagated: %+v", got)
	}
}

func TestTIChecker_Check_LegacyEntryZeroIndicatorID(t *testing.T) {
	t.Parallel()

	// A legacy cache entry without a stored id leaves IndicatorID at zero; the
	// match still fires but the downstream audit row is skipped.
	cache := &fakeTICache{lookup: valkey.DomainLookup{
		Blocked:    true,
		RiskScore:  85,
		ThreatType: "malware",
	}}
	checker := NewTIChecker(cache, zerolog.Nop())

	got, err := checker.Check(context.Background(), "https://legacy.example/")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if got.IndicatorID != 0 {
		t.Errorf("legacy entry must yield IndicatorID 0, got %d", got.IndicatorID)
	}
}

func TestTIChecker_Check_LookupErrorDegradesToNoMatch(t *testing.T) {
	t.Parallel()

	cache := &fakeTICache{err: errors.New("valkey down")}
	checker := NewTIChecker(cache, zerolog.Nop())

	got, err := checker.Check(context.Background(), "https://example.com/")
	if err != nil {
		t.Fatalf("Check must degrade gracefully, got error: %v", err)
	}
	if got.Matched || got.IndicatorID != 0 {
		t.Errorf("lookup error must yield empty TIResult, got %+v", got)
	}
}
