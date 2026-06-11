package header

import (
	"context"
	"testing"
	"time"

	"github.com/saif/cybersiren/internal/phishing/enricher"
)

func TestDomainAgeFromRegistration(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 6, 10, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		raw      string
		wantDays int
		wantOK   bool
	}{
		{"rfc3339", "2025-06-01T00:00:00Z", 9, true},
		{"date only", "2024-06-10", 365, true},
		{"space separated", "2025-05-11 12:00:00", 30, true},
		{"dd-Mon-yyyy", "11-May-2025", 30, true},
		{"registered today", "2025-06-10T00:00:00Z", 0, true},
		{"empty", "", 0, false},
		{"unparseable", "not-a-date", 0, false},
		{"future date is unknown", "2030-01-01T00:00:00Z", 0, false},
		{"whitespace only", "   ", 0, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotDays, gotOK := domainAgeFromRegistration(tc.raw, now)
			if gotOK != tc.wantOK {
				t.Fatalf("ok = %v, want %v (days=%d)", gotOK, tc.wantOK, gotDays)
			}
			if gotOK && gotDays != tc.wantDays {
				t.Errorf("days = %d, want %d", gotDays, tc.wantDays)
			}
		})
	}
}

func TestEnricherDomainAgeLooker_EmptyDomain(t *testing.T) {
	t.Parallel()
	// A blank domain must short-circuit before any WHOIS call.
	_, ok := EnricherDomainAgeLooker{}.DomainAgeDays(t.Context(), "  ")
	if ok {
		t.Errorf("empty domain must return ok=false")
	}
}

// TestEnricherDomainAgeLooker_CancelledContextDegrades proves the WHOIS lookup
// degrades gracefully (returns ok=false, no hang, no panic) when the caller's
// context is already cancelled — the same path live smoke hits on a network
// failure or a 5s timeout. The shared enricher swallows the error and yields a
// zero-value result, which domainAgeFromRegistration maps to "unknown".
//
// We inject a fake WHOIS func that RESPECTS ctx (returns a zero-value result the
// instant the context is done) instead of calling the real enricher. The real
// enricher.LookupWHOIS dials WHOIS in a goroutine that ignores ctx, so exercising
// it here would do a real network dial and leak that goroutine while the test
// "passes" on the select's ctx.Done() branch. The fake keeps the test fully
// offline and deterministic while still asserting the degrade contract.
func TestEnricherDomainAgeLooker_CancelledContextDegrades(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before the lookup runs

	var called bool
	looker := EnricherDomainAgeLooker{
		whois: func(ctx context.Context, _ string) enricher.WHOISResult {
			called = true
			// Respect the caller's context: a cancelled ctx yields no data,
			// exactly as the real enricher does once its 5s deadline fires.
			select {
			case <-ctx.Done():
				return enricher.WHOISResult{}
			default:
				return enricher.WHOISResult{RegistrationDate: "2020-01-01T00:00:00Z"}
			}
		},
	}

	days, ok := looker.DomainAgeDays(ctx, "domain-age-degrade.test")
	if !called {
		t.Fatal("expected the injected WHOIS func to be invoked")
	}
	if ok {
		t.Errorf("a cancelled-context WHOIS lookup must degrade to ok=false, got days=%d", days)
	}
}
