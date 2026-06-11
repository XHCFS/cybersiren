// Package header contains the pure signal extractors for SVC-04.
//
// "Pure" here means: no DB, no Kafka, no filesystem, no time.Now() unless
// passed in. Extractors take an AnalysisHeadersMessage and return typed
// signal structs that the rule evaluator can reason about.
//
// Why pure? Because every extractor is exercised by table-driven unit
// tests, and these are the foundation for SVC-04's auditability.
package header

import (
	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// AuthResult enumerates the canonical SPF/DKIM/DMARC/ARC results.
type AuthResult string

const (
	AuthResultPass     AuthResult = "pass"
	AuthResultFail     AuthResult = "fail"
	AuthResultSoftfail AuthResult = "softfail"
	AuthResultNone     AuthResult = "none"
	AuthResultMissing  AuthResult = ""
)

// AuthSignals captures dimension (i): authentication verification.
type AuthSignals struct {
	SPF                 AuthResult
	DKIM                AuthResult
	DMARC               AuthResult
	ARC                 AuthResult
	FromReplyToMatch    bool
	FromReturnPathMatch bool
	// HasReplyTo / HasReturnPath let the rule evaluator distinguish
	// "no Reply-To at all" from "Reply-To matches From".
	HasReplyTo    bool
	HasReturnPath bool
}

// ReputationSignals captures dimension (ii): sender reputation.
type ReputationSignals struct {
	SenderDomain       string
	OriginatingIP      string
	XOriginatingIP     string
	TIDomainMatch      bool
	TIDomainRiskScore  int
	TIDomainThreatType string
	TIIPMatch          bool
	TIIPRiskScore      int
	TIIPThreatType     string
	IsFreeProvider     bool
	TyposquatTarget    string
	TyposquatDistance  int // 0 = no typosquat detected
	// DomainAgeDays is intentionally a *int. It is populated from a live
	// WHOIS lookup (reputation.go via the shared enricher). nil now means a
	// WHOIS miss/unavailable (5s timeout, no creation date in the record, or
	// the lookup was skipped for a free provider) — distinct from age 0 (a
	// domain registered today). See ARCH-SPEC §13.
	DomainAgeDays *int
}

// StructuralSignals captures dimension (iii): structural anomalies.
type StructuralSignals struct {
	HopCount                int
	HopCountAboveThreshold  bool
	TimeDriftHours          float64
	TimeDriftAboveThreshold bool
	HasVendorSecurityTag    bool
	VendorTagNames          []string
	MailerAgent             string
	MissingMailer           bool
	SuspiciousMailerAgent   bool
	NonASCIISenderDomain    bool

	// Body-derived structural signals (D9 — computed HERE in SVC-04 from the
	// body the parser ships on analysis.headers, NOT by the parser). See
	// ARCH-SPEC §1 step 3b dimension (iii): "HTML-only messages, hidden text
	// elements, embedded forms, encoding anomalies".
	HTMLOnly        bool // message has an HTML part but no meaningful plain-text alternative
	HasHiddenText   bool // HTML contains visually-hidden text (display:none / font-size:0 / white-on-white / off-screen)
	HasForm         bool // HTML embeds a <form> (credential-harvest vector)
	EncodingAnomaly bool // declared/observed charset mismatch or excessive non-printable content
}

// HeaderSignals is the union of all three dimensions plus a back-pointer
// to the original message for any rule that needs to inspect raw fields.
type HeaderSignals struct {
	Auth       AuthSignals
	Reputation ReputationSignals
	Structural StructuralSignals
	Source     *contractsk.AnalysisHeadersMessage
}

// AsContract converts internal signals into the wire format used in
// scores.header.signals. It's separate from the internal struct so we
// can evolve the wire format independently of the in-memory shape.
func (s HeaderSignals) AsContract() contractsk.HeaderSignals {
	out := contractsk.HeaderSignals{
		SPFResult:           string(s.Auth.SPF),
		DKIMResult:          string(s.Auth.DKIM),
		DMARCResult:         string(s.Auth.DMARC),
		FromReplyToMatch:    s.Auth.FromReplyToMatch,
		FromReturnPathMatch: s.Auth.FromReturnPathMatch,
		IsFreeProvider:      s.Reputation.IsFreeProvider,
		HopCount:            s.Structural.HopCount,
		TimeDriftHours:      s.Structural.TimeDriftHours,
	}
	if s.Reputation.DomainAgeDays != nil {
		v := *s.Reputation.DomainAgeDays
		out.DomainAgeDays = &v
	}
	if s.Reputation.TyposquatDistance > 0 && s.Reputation.TyposquatTarget != "" {
		t := s.Reputation.TyposquatTarget
		d := s.Reputation.TyposquatDistance
		out.TyposquatTarget = &t
		out.TyposquatDistance = &d
	}
	return out
}
