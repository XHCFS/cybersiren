package header

import (
	"context"
	"errors"
	"strings"

	"github.com/rs/zerolog"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/normalization"
	"github.com/saif/cybersiren/shared/valkey"
)

// TILookup is the minimal interface SVC-04 needs from the TI cache.
//
// We accept the interface (rather than the concrete *valkey.ValkeyTICache)
// so unit tests can pass fakes without touching Redis. The shape matches
// shared/valkey.TICache.IsBlocklisted.
type TILookup interface {
	IsBlocklisted(ctx context.Context, domain string) (bool, int, string, error)
}

// Compile-time check.
var _ TILookup = (*valkey.ValkeyTICache)(nil)

// ReputationExtractor turns a parsed header message into ReputationSignals.
type ReputationExtractor struct {
	tiLookup             TILookup
	typosquatMaxDistance int
	log                  zerolog.Logger
}

// NewReputationExtractor builds an extractor.
//
// tiLookup may be nil — that disables TI-based reputation entirely (the
// extractor still runs typosquat / free-provider detection so unit tests
// don't need a Redis fixture).
func NewReputationExtractor(tiLookup TILookup, typosquatMaxDistance int, log zerolog.Logger) *ReputationExtractor {
	if typosquatMaxDistance < 0 {
		typosquatMaxDistance = 0
	}
	return &ReputationExtractor{
		tiLookup:             tiLookup,
		typosquatMaxDistance: typosquatMaxDistance,
		log:                  log,
	}
}

// Extract is the entry point. It is allowed to call out to Redis but
// MUST NOT escalate any TI-cache miss into a fatal error — per ARCH-SPEC
// §6, a TI miss is treated as "no match".
func (r *ReputationExtractor) Extract(ctx context.Context, msg *contractsk.AnalysisHeadersMessage) ReputationSignals {
	if msg == nil {
		return ReputationSignals{}
	}

	signals := ReputationSignals{
		SenderDomain:   normalization.NormalizeDomain(msg.SenderDomain),
		OriginatingIP:  strings.TrimSpace(msg.OriginatingIP),
		XOriginatingIP: strings.TrimSpace(msg.XOriginatingIP),
	}

	// Free-provider classification works purely off the embedded list.
	if signals.SenderDomain != "" {
		signals.IsFreeProvider = IsFreeProvider(signals.SenderDomain)
	}

	// Typosquat detection runs against the embedded brand list.
	if signals.SenderDomain != "" && r.typosquatMaxDistance > 0 {
		// Free-provider domains are deliberately exempted: gmail.com is
		// distance 0 from itself, but distance 1 from "gmaiI.com" — we
		// don't want the brand list to mask legitimate gmail mail.
		if !signals.IsFreeProvider {
			tgt, dist := FindTyposquat(signals.SenderDomain, r.typosquatMaxDistance)
			if dist > 0 {
				signals.TyposquatTarget = tgt
				signals.TyposquatDistance = dist
			}
		}
	}

	// TI domain lookup — best-effort.
	if r.tiLookup != nil && signals.SenderDomain != "" {
		hit, score, threat, err := r.tiLookup.IsBlocklisted(ctx, signals.SenderDomain)
		if err != nil {
			// Cache miss / Valkey down => no match. Log at debug so we
			// don't drown the logs in scoring runs.
			r.log.Debug().
				Err(err).
				Str("sender_domain", signals.SenderDomain).
				Msg("ti domain lookup failed; treating as no match")
		} else if hit {
			signals.TIDomainMatch = true
			signals.TIDomainRiskScore = score
			signals.TIDomainThreatType = threat
		}
	}

	// IP TI is treated identically to domain TI: feed cache covers both
	// kinds via the same key namespace. We use the originating_ip first;
	// fall back to x_originating_ip when the former is absent.
	ipForLookup := signals.OriginatingIP
	if ipForLookup == "" {
		ipForLookup = signals.XOriginatingIP
	}
	if r.tiLookup != nil && ipForLookup != "" {
		hit, score, threat, err := r.tiLookup.IsBlocklisted(ctx, ipForLookup)
		if err != nil {
			r.log.Debug().
				Err(err).
				Str("originating_ip", ipForLookup).
				Msg("ti ip lookup failed; treating as no match")
		} else if hit {
			signals.TIIPMatch = true
			signals.TIIPRiskScore = score
			signals.TIIPThreatType = threat
		}
	}

	// DomainAgeDays remains nil. ARCH-SPEC §13 calls out that
	// ti_indicators.first_seen is feed-observation time, not WHOIS
	// registration. SVC-04 does not perform live WHOIS (per "What NOT
	// to do"). Marking as a documented spec gap.
	signals.DomainAgeDays = nil

	return signals
}

// ErrTILookupUnavailable is returned by stub TI lookups that want to
// signal "not configured" without bringing Valkey into the test setup.
var ErrTILookupUnavailable = errors.New("ti lookup unavailable")
