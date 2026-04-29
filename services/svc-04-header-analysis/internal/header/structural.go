package header

import (
	"encoding/json"
	"math"
	"strings"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// StructuralExtractorConfig tunes structural-anomaly thresholds.
type StructuralExtractorConfig struct {
	HopCountThreshold       int
	TimeDriftHoursThreshold float64
}

// ExtractStructural runs dimension (iii). All inputs come from the Kafka
// message; no I/O is performed.
//
// Spec note: any structural signal that requires email *body* content
// (HTML hidden elements, embedded forms, …) is intentionally NOT
// implemented here — those fields aren't present on analysis.headers and
// are the responsibility of SVC-06 (NLP). See ARCH-SPEC §1 step 3b.
func ExtractStructural(msg *contractsk.AnalysisHeadersMessage, cfg StructuralExtractorConfig) StructuralSignals {
	if msg == nil {
		return StructuralSignals{}
	}

	signals := StructuralSignals{
		HopCount:    msg.HopCount,
		MailerAgent: strings.TrimSpace(msg.MailerAgent),
	}

	if cfg.HopCountThreshold > 0 && signals.HopCount > cfg.HopCountThreshold {
		signals.HopCountAboveThreshold = true
	}

	signals.TimeDriftHours = computeTimeDrift(msg)
	if cfg.TimeDriftHoursThreshold > 0 && math.Abs(signals.TimeDriftHours) > cfg.TimeDriftHoursThreshold {
		signals.TimeDriftAboveThreshold = true
	}

	tagNames := extractVendorTagNames(msg.VendorSecurityTags)
	if len(tagNames) == 0 {
		tagNames = extractVendorTagNamesFromHeaders(msg.HeadersJSON)
	}
	if len(tagNames) > 0 {
		signals.HasVendorSecurityTag = true
		signals.VendorTagNames = tagNames
	}

	if signals.MailerAgent == "" {
		signals.MissingMailer = true
	} else {
		signals.SuspiciousMailerAgent = isSuspiciousMailer(signals.MailerAgent)
	}

	return signals
}

// computeTimeDrift returns |sent_timestamp − last_received_timestamp|
// expressed in hours. When either timestamp is missing, returns 0 — the
// rule evaluator can decide how to react via a "missing timestamp" rule.
func computeTimeDrift(msg *contractsk.AnalysisHeadersMessage) float64 {
	if msg == nil || msg.SentTimestamp <= 0 {
		return 0
	}

	var latestReceived int64
	for _, hop := range msg.ReceivedChain {
		if hop.Timestamp > latestReceived {
			latestReceived = hop.Timestamp
		}
	}
	if latestReceived <= 0 {
		return 0
	}

	deltaSeconds := float64(latestReceived - msg.SentTimestamp)
	return deltaSeconds / 3600.0
}

// extractVendorTagNames pulls the top-level keys out of vendor_security_tags.
// We don't make assumptions about which providers populate it; the rule
// evaluator can match on specific names ("X-Microsoft-Antispam", etc.).
func extractVendorTagNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	out := make([]string, 0, len(generic))
	for k := range generic {
		k = strings.TrimSpace(k)
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// extractVendorTagNamesFromHeaders walks raw headers_json looking for
// well-known anti-spam header names. This is a best-effort fallback when
// vendor_security_tags is absent.
func extractVendorTagNamesFromHeaders(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	known := []string{
		"X-Microsoft-Antispam",
		"X-Microsoft-Antispam-Mailbox-Delivery",
		"X-Forefront-Antispam-Report",
		"X-MS-Exchange-Organization-AuthAs",
		"X-MS-Exchange-Organization-AuthSource",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Flag",
		"X-Spam-Level",
		"X-Proofpoint-Spam-Details",
		"X-Mimecast-Spam-Score",
		"X-Mailer-Sender",
	}
	known = canonicalKeys(known)
	out := make([]string, 0, 4)
	canon := canonicalKeyMap(generic)
	for _, k := range known {
		if _, ok := canon[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

func canonicalKeys(in []string) []string {
	out := make([]string, 0, len(in))
	for _, k := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(k)))
	}
	return out
}

func canonicalKeyMap(m map[string]json.RawMessage) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
	}
	return out
}

// isSuspiciousMailer flags a few well-known scam tooling user-agents and
// generic placeholders. The list is intentionally short — the rule
// evaluator can match more patterns via the rules table.
func isSuspiciousMailer(mailer string) bool {
	v := strings.ToLower(mailer)
	suspicious := []string{
		"phpmailer",
		"mass-mailer",
		"bulk-mail",
		"send-safe",
		"darkmailer",
		"the bat!",
		"x-mailer",
		"unknown",
	}
	for _, s := range suspicious {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}
