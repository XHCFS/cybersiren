package header

import (
	"context"
	"strings"
	"time"

	"github.com/saif/cybersiren/internal/phishing/enricher"
)

// DomainAgeLooker resolves the age (in days) of a sender domain's registration.
//
// SVC-04 does NOT own a WHOIS client — the registration date comes from the
// existing enricher (internal/phishing/enricher, already used by SVC-03), which
// keeps its own 24h in-process TTL cache and 5s timeout and never propagates
// errors. We depend on the small interface here, rather than the concrete
// enricher, so reputation extraction stays pure and unit-testable: tests inject
// a deterministic looker and never touch the network.
//
// Returns (ageDays, true) when a registration date was resolved and parsed;
// (0, false) on any miss (no WHOIS data, unparseable date, lookup unavailable).
type DomainAgeLooker interface {
	DomainAgeDays(ctx context.Context, domain string) (int, bool)
}

// EnricherDomainAgeLooker adapts the shared WHOIS enricher to DomainAgeLooker.
// It reuses enricher.LookupWHOIS (likexian/whois) — the very client SVC-03 uses
// — including its internal cache; SVC-04 builds no new WHOIS client (P2.3 / D-WHOIS).
type EnricherDomainAgeLooker struct{}

// DomainAgeDays looks up the sender domain via the shared enricher and converts
// the registration date string into an age in whole days relative to now.
func (EnricherDomainAgeLooker) DomainAgeDays(ctx context.Context, domain string) (int, bool) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return 0, false
	}
	res := enricher.LookupWHOIS(ctx, domain)
	return domainAgeFromRegistration(res.RegistrationDate, time.Now())
}

// whoisDateLayouts lists the timestamp formats WHOIS registries emit for the
// creation date. whois-parser already normalises most registrars to RFC3339,
// but a handful return date-only or space-separated forms, so we try a small
// ordered set and accept the first that parses.
var whoisDateLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"2006-01-02T15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"2006.01.02",
	"2006/01/02",
}

// domainAgeFromRegistration parses a WHOIS registration-date string and returns
// the age in whole days at `now`. It is the pure core of the looker so it can
// be unit-tested without any network or clock dependency.
//
// A blank string, an unparseable date, or a future registration date all yield
// (0, false) — "unknown", which the rule layer treats as "no domain-age signal"
// rather than "age 0". A domain registered today legitimately yields (0, true).
func domainAgeFromRegistration(raw string, now time.Time) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	var reg time.Time
	var ok bool
	for _, layout := range whoisDateLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			reg = t
			ok = true
			break
		}
	}
	if !ok {
		return 0, false
	}
	// A registration date in the future is nonsense (registry clock skew or a
	// parse landing on the wrong layout); treat it as unknown rather than
	// emitting a negative age that would confuse the rule layer.
	if reg.After(now) {
		return 0, false
	}
	days := int(now.Sub(reg).Hours() / 24)
	if days < 0 {
		return 0, false
	}
	return days, true
}
