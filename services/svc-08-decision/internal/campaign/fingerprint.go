// Package campaign implements campaign fingerprinting, near-duplicate
// detection (SimHash), and reputation-based score nudging for SVC-08.
//
// See docs/design/svc-07-08-design-brief.md §3.8 and ARCH-SPEC §8 for
// the contract.
package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Inputs is the minimal set of fields needed to compute a campaign
// fingerprint. They are extracted from emails.scored.component_details
// by the engine before any DB or rule evaluation.
type Inputs struct {
	SenderDomain string
	URLDomain    string
	Subject      string
	Intent       string
}

// Fingerprint computes the deterministic SHA-256 campaign fingerprint
// per ARCH-SPEC §8.1:
//
//	fingerprint = SHA256( sender_domain | url_domain | SHA256(subject_template) | intent )
//
// All fields are lowercased; empty strings are substituted for missing
// fields (per design brief §3.8.1, "a partial fingerprint is better
// than no campaign tracking"). Returns the fingerprint as a 64-char
// lowercase hex string.
func Fingerprint(in Inputs) string {
	subjectTpl := normaliseSubject(in.Subject)
	subjectInner := sha256.Sum256([]byte(subjectTpl))
	subjectHex := hex.EncodeToString(subjectInner[:])

	parts := strings.Join([]string{
		strings.ToLower(in.SenderDomain),
		strings.ToLower(in.URLDomain),
		subjectHex,
		strings.ToLower(in.Intent),
	}, "|")

	sum := sha256.Sum256([]byte(parts))
	return hex.EncodeToString(sum[:])
}

// ExtractInputs parses the upstream component_details and pulls the
// fields the fingerprint needs. Each lookup is best-effort — a missing
// field becomes an empty string.
func ExtractInputs(d contracts.ComponentDetails) Inputs {
	return Inputs{
		SenderDomain: extractSenderDomain(d.Header),
		URLDomain:    extractPrimaryURLDomain(d.URL),
		Subject:      extractSubject(d),
		Intent:       extractIntent(d.NLP),
	}
}

// ExtractBody returns a normalised body string for SimHash. Returns
// (text, true) when at least the subject + a body segment is present;
// (zero, false) when the upstream NLP message had no usable content.
func ExtractBody(d contracts.ComponentDetails) (string, bool) {
	subject := extractSubject(d)
	body := extractNLPField(d.NLP, "plain_text")
	if body == "" {
		body = extractNLPField(d.NLP, "normalised_body")
	}
	if body == "" && subject == "" {
		return "", false
	}
	combined := strings.ToLower(strings.TrimSpace(subject + " " + body))
	if combined == "" {
		return "", false
	}
	return combined, true
}

// normaliseSubject applies the steps from design brief §3.8.2:
//  1. Lowercase.
//  2. Strip leading "Re:", "Fwd:", "[EXTERNAL]" and similar prefixes.
//  3. Replace runs of ≥3 digits with {N}.
//  4. Replace UUIDs with {UUID}.
//  5. Replace email addresses with {EMAIL}.
//
// The normalised form is hashed (not stored) into the inner SHA-256.
func normaliseSubject(s string) string {
	s = strings.ToLower(s)
	for {
		trimmed := subjectPrefixRE.ReplaceAllString(s, "")
		if trimmed == s {
			break
		}
		s = strings.TrimSpace(trimmed)
	}
	s = uuidRE.ReplaceAllString(s, "{uuid}")
	s = emailRE.ReplaceAllString(s, "{email}")
	s = digitsRE.ReplaceAllString(s, "{n}")
	return strings.TrimSpace(s)
}

var (
	subjectPrefixRE = regexp.MustCompile(`(?i)^\s*(re:|fwd:|fw:|\[external\]|\[ext\]|\[spam\])\s*`)
	digitsRE        = regexp.MustCompile(`\d{3,}`)
	uuidRE          = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	emailRE         = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
)

// ----------------------------------------------------------------------
// Field extractors — each tolerates missing/malformed JSON.
// ----------------------------------------------------------------------

// extractSenderDomain pulls signals.sender_domain (svc-04 nests it inside
// a "signals" object on ScoresHeaderMessage). Falls back to a top-level
// "sender_domain" if the upstream shape ever changes.
func extractSenderDomain(headerRaw json.RawMessage) string {
	if len(headerRaw) == 0 {
		return ""
	}
	var hdr struct {
		Signals struct {
			SenderDomain string `json:"sender_domain"`
		} `json:"signals"`
		SenderDomain string `json:"sender_domain"`
	}
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return ""
	}
	if hdr.Signals.SenderDomain != "" {
		return hdr.Signals.SenderDomain
	}
	return hdr.SenderDomain
}

// extractPrimaryURLDomain pulls the primary URL domain from
// component_details.url. The svc-03 ScoreEnvelope.Details map carries
// a "per_url" array; we take the highest-scoring entry's domain.
func extractPrimaryURLDomain(urlRaw json.RawMessage) string {
	if len(urlRaw) == 0 {
		return ""
	}
	var env struct {
		Details struct {
			PerURL []struct {
				URL   string `json:"url"`
				Score int    `json:"score"`
			} `json:"per_url"`
		} `json:"details"`
	}
	if err := json.Unmarshal(urlRaw, &env); err != nil {
		return ""
	}
	bestScore := -1
	bestDomain := ""
	for _, u := range env.Details.PerURL {
		if u.Score <= bestScore {
			continue
		}
		domain := domainOf(u.URL)
		if domain == "" {
			continue
		}
		bestScore = u.Score
		bestDomain = domain
	}
	return bestDomain
}

// extractSubject pulls the subject from any component that carries it.
// SVC-06 includes it in details.subject (currently); we also probe the
// header signals as a fallback.
func extractSubject(d contracts.ComponentDetails) string {
	if s := extractNLPField(d.NLP, "subject"); s != "" {
		return s
	}
	if len(d.Header) > 0 {
		var hdr struct {
			Subject string `json:"subject"`
			Signals struct {
				Subject string `json:"subject"`
			} `json:"signals"`
		}
		if err := json.Unmarshal(d.Header, &hdr); err == nil {
			if hdr.Subject != "" {
				return hdr.Subject
			}
			if hdr.Signals.Subject != "" {
				return hdr.Signals.Subject
			}
		}
	}
	return ""
}

// extractIntent pulls the first intent label from component_details.nlp
// (intent_labels is published as a string array by svc-06).
func extractIntent(nlpRaw json.RawMessage) string {
	if len(nlpRaw) == 0 {
		return ""
	}
	var env struct {
		Details struct {
			IntentLabels []string `json:"intent_labels"`
			Intent       string   `json:"intent"`
		} `json:"details"`
	}
	if err := json.Unmarshal(nlpRaw, &env); err != nil {
		return ""
	}
	if env.Details.Intent != "" {
		return env.Details.Intent
	}
	if len(env.Details.IntentLabels) > 0 {
		return env.Details.IntentLabels[0]
	}
	return ""
}

// extractNLPField reads a string-valued key from the NLP envelope's
// details map, returning "" on miss or non-string value.
func extractNLPField(nlpRaw json.RawMessage, field string) string {
	if len(nlpRaw) == 0 {
		return ""
	}
	var env struct {
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(nlpRaw, &env); err != nil {
		return ""
	}
	if env.Details == nil {
		return ""
	}
	if v, ok := env.Details[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// domainOf returns the lowercased host portion of a URL string. Returns
// "" when the URL cannot be parsed or has no host.
func domainOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Try once more, prefixed with "//" so url.Parse treats the
		// leading domain as a host even without a scheme.
		if u2, err2 := url.Parse("//" + raw); err2 == nil && u2.Host != "" {
			return strings.ToLower(strings.TrimPrefix(u2.Host, "www."))
		}
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(u.Host, "www."))
}
