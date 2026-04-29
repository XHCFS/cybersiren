package header

import (
	"strings"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// ExtractAuth derives AuthSignals from analysis.headers.
//
// It NEVER fails: missing or malformed values are surfaced as
// AuthResultMissing / boolean false, leaving the decision of how to
// react to the rule evaluator and the rules table.
func ExtractAuth(msg *contractsk.AnalysisHeadersMessage) AuthSignals {
	if msg == nil {
		return AuthSignals{}
	}

	signals := AuthSignals{
		SPF:   normalizeAuthResult(msg.AuthSPF),
		DKIM:  normalizeAuthResult(msg.AuthDKIM),
		DMARC: normalizeAuthResult(msg.AuthDMARC),
		ARC:   normalizeAuthResult(msg.AuthARC),
	}

	fromDomain := domainOf(msg.SenderEmail)
	if fromDomain == "" {
		fromDomain = strings.ToLower(strings.TrimSpace(msg.SenderDomain))
	}

	replyToDomain := domainOf(msg.ReplyToEmail)
	signals.HasReplyTo = replyToDomain != ""
	if signals.HasReplyTo && fromDomain != "" {
		// Treat "From-domain == Reply-To-domain" as alignment. We compare
		// at registrable-domain granularity by stripping leading subdomains
		// of the longer label set, but since brand impersonations also
		// happen at registrable-domain level, exact domain match is the
		// most conservative signal we can emit purely from headers.
		signals.FromReplyToMatch = sameRegistrableDomain(fromDomain, replyToDomain)
	}

	returnPathDomain := domainOf(msg.ReturnPath)
	signals.HasReturnPath = returnPathDomain != ""
	if signals.HasReturnPath && fromDomain != "" {
		signals.FromReturnPathMatch = sameRegistrableDomain(fromDomain, returnPathDomain)
	}

	return signals
}

// normalizeAuthResult lowercases the input and maps known aliases to one
// of the canonical AuthResult values. Unknown values map to "" (missing).
func normalizeAuthResult(raw string) AuthResult {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "":
		return AuthResultMissing
	case "pass":
		return AuthResultPass
	case "fail", "permerror", "perm-error":
		return AuthResultFail
	case "softfail", "soft-fail":
		return AuthResultSoftfail
	case "none", "neutral", "temperror", "temp-error", "policy":
		return AuthResultNone
	default:
		return AuthResultNone
	}
}

// domainOf returns the domain part of an RFC822 address-like string. It
// is intentionally lenient — header parsing has already happened in
// SVC-02; we just need a best-effort extraction.
func domainOf(addr string) string {
	v := strings.TrimSpace(addr)
	if v == "" {
		return ""
	}

	// Strip surrounding angle brackets / display name.
	if start := strings.Index(v, "<"); start >= 0 {
		if end := strings.Index(v[start:], ">"); end > 0 {
			v = v[start+1 : start+end]
		}
	}

	at := strings.LastIndex(v, "@")
	if at < 0 {
		// Permit a bare domain (e.g. "example.com") so this helper is
		// reusable for domain-only values such as Return-Path.
		return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(v), "<"), ">"))
	}

	dom := strings.ToLower(strings.TrimSpace(v[at+1:]))
	dom = strings.Trim(dom, ".")
	dom = strings.TrimSuffix(dom, ">")
	return dom
}

// sameRegistrableDomain compares two normalised domains. It returns true
// when either domain equals the other, OR when one is a strict subdomain
// of the other AND the shared suffix has at least two labels — a cheap
// proxy for "same registrable domain" without pulling in the public
// suffix list.
func sameRegistrableDomain(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if hasSuffixDot(a, b) || hasSuffixDot(b, a) {
		// Require at least two labels in the shared suffix.
		shared := a
		if hasSuffixDot(b, a) {
			shared = a
		} else {
			shared = b
		}
		return strings.Count(shared, ".") >= 1
	}
	return false
}

// hasSuffixDot returns true when s ends with "." + suffix.
func hasSuffixDot(s, suffix string) bool {
	if len(s) <= len(suffix) {
		return false
	}
	return strings.HasSuffix(s, "."+suffix)
}
