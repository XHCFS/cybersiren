package header

import (
	"testing"
	"time"
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
