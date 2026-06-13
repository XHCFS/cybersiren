package engine

import dbsqlc "github.com/saif/cybersiren/db/sqlc"

// Label is the SVC-08 verdict-label string. We re-export here as a
// distinct type so the engine can be tested without depending on the
// generated DB types in test fixtures, but the values match the
// dbsqlc.VerdictLabel enum exactly.
type Label string

const (
	LabelBenign     Label = "benign"
	LabelSuspicious Label = "suspicious"
	LabelPhishing   Label = "phishing"
	LabelMalware    Label = "malware"
	// LabelSpam / LabelUnknown exist in the verdict_label enum but are
	// reserved for analyst overrides — never assigned by the automated
	// pipeline. See design brief §3.6.
)

// LabelFor maps a final risk_score (0..100) to the verdict label per
// design brief §3.6. Boundary convention: lower band wins (score=25 →
// benign; score=26 → suspicious; score=51 → phishing; score=76 →
// malware).
func LabelFor(score int) Label {
	switch {
	case score <= 25:
		return LabelBenign
	case score <= 50:
		return LabelSuspicious
	case score <= 75:
		return LabelPhishing
	default:
		return LabelMalware
	}
}

// ReconcileLabel refines the verdict label inside the high-risk band so the
// pipeline distinguishes "phishing(high)" from "malware" per design brief §3.6.
// Bands 0–75 are returned verbatim; only the malware band (76–100) is split:
//
//   - LabelMalware  — a high, malware-grade attachment is present (see
//     hasHighAttachment). It wins even when a URL/header/NLP signal scored
//     higher, because the malicious attachment is the more actionable threat.
//   - LabelPhishing — otherwise (high score driven by URL/header/NLP signals
//     with no malware-grade attachment, i.e. phishing(high)).
//
// This refines only the persisted/wire label; confidence MUST stay on the
// score's natural band — see verdictLabelAndConfidence for the why.
func ReconcileLabel(score int, c Components) Label {
	return reconcile(LabelFor(score), c)
}

// reconcile applies the malware-vs-phishing split to an already-computed
// natural-band label, so the hot path can derive the band once and feed it to
// both the reconcile and the confidence formula without recomputing LabelFor.
func reconcile(natural Label, c Components) Label {
	if natural != LabelMalware {
		return natural
	}
	if hasHighAttachment(c) {
		return LabelMalware
	}
	return LabelPhishing
}

// hasHighAttachment reports whether the email carries a malware-grade
// attachment: the attachment component is present (a nil component is "absent",
// not 0) and is itself in the malware band. The floor is taken from
// LabelBand(LabelMalware) so it can never drift from LabelFor's band edges.
func hasHighAttachment(c Components) bool {
	floor, _ := LabelBand(LabelMalware)
	return c.Attachment != nil && *c.Attachment >= floor
}

// verdictLabelAndConfidence computes the persisted/wire verdict label and its
// confidence for a final score. Both the main (Handle) and degraded
// (publishDegraded) paths go through this single seam, so the two cannot drift
// and one set of tests covers the invariant below.
//
// CONFIDENCE TRAP: the label is reconciled (malware vs phishing(high) in the
// 76–100 band per §3.6), but confidence is computed against the score's NATURAL
// band, never the reconciled label. Threading the reconciled label in would
// measure an 85 reclassified to phishing against the 51–75 band and collapse
// confidence toward 0. The natural band is bound to `natural` once and passed
// straight to Confidence; there is deliberately no reconciled-label variable in
// scope to thread in by mistake. See §3.6/§3.7.
func verdictLabelAndConfidence(finalScore int, c Components, partialAnalysis bool, source string) (Label, float64) {
	natural := LabelFor(finalScore)
	return reconcile(natural, c), Confidence(finalScore, natural, partialAnalysis, source)
}

// LabelBand returns the [lower, upper] threshold bounds of the label's
// score band. Used by the confidence formula to compute distance from
// the nearest threshold.
func LabelBand(label Label) (lower, upper int) {
	switch label {
	case LabelBenign:
		return 0, 25
	case LabelSuspicious:
		return 26, 50
	case LabelPhishing:
		return 51, 75
	case LabelMalware:
		return 76, 100
	}
	return 0, 100
}

// AsDBLabel returns the dbsqlc.VerdictLabel matching the engine label.
// Spam / unknown labels are not produced by the engine, so they round
// trip through the engine type system as plain strings if ever needed.
func (l Label) AsDBLabel() dbsqlc.VerdictLabel {
	return dbsqlc.VerdictLabel(string(l))
}
