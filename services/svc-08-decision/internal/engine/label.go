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

// ReconcileLabel refines the verdict label inside the high-risk band so
// the pipeline distinguishes "phishing(high)" from "malware" per design
// brief §3.6. It returns LabelFor(score) unchanged for every band except
// the malware band (76–100), where it returns:
//
//   - LabelMalware  — only when the attachment component is the dominant
//     high driver of the score (see attachmentIsDominantHigh).
//   - LabelPhishing — otherwise (the high score is driven by URL/header/
//     NLP signals, i.e. phishing(high)).
//
// Bands 0–75 are returned verbatim; this is purely a malware-vs-phishing
// disambiguation of the top band.
//
// IMPORTANT: this changes only the persisted/wire label string. Confidence
// must still be computed against the SCORE's natural band via
// Confidence(score, LabelFor(score), …) — passing the reconciled phishing
// label for an 85 score would collapse confidence to 0. See §3.6/§3.7.
func ReconcileLabel(score int, c Components) Label {
	base := LabelFor(score)
	if base != LabelMalware {
		return base
	}
	if attachmentIsDominantHigh(c) {
		return LabelMalware
	}
	return LabelPhishing
}

// attachmentIsDominantHigh reports whether the attachment component is
// the dominant high driver of the blended score. It is true iff the
// attachment score is present, is itself in the malware band (≥ 76, the
// malware-band floor), and is ≥ every other PRESENT component (a nil
// component is not "present" and is ignored; if attachment is the only
// present component it is trivially the max). Ties go to attachment
// (>=), so an attachment tied with another high component still yields
// malware — the more severe of the two equally-plausible labels.
func attachmentIsDominantHigh(c Components) bool {
	if c.Attachment == nil || *c.Attachment < 76 {
		return false
	}
	att := *c.Attachment
	if c.URL != nil && *c.URL > att {
		return false
	}
	if c.Header != nil && *c.Header > att {
		return false
	}
	if c.NLP != nil && *c.NLP > att {
		return false
	}
	return true
}

// verdictLabelAndConfidence computes the persisted/wire verdict label and
// its confidence for a final score. This is the single seam both the main
// (Handle) and degraded (publishDegraded) paths use, so the two CANNOT
// drift apart and the confidence-trap invariant is exercised by one set of
// tests.
//
// The label is RECONCILED (malware vs phishing(high) in the 76–100 band per
// §3.6). The confidence is deliberately computed against the score's NATURAL
// band — Confidence(finalScore, LabelFor(finalScore), …) — NOT the reconciled
// label. Threading the reconciled label into Confidence is the regression the
// brief warns about: an 85 reclassified to phishing would measure distance
// against the 51–75 band and collapse confidence toward 0. See §3.6/§3.7.
func verdictLabelAndConfidence(finalScore int, c Components, partialAnalysis bool, source string) (Label, float64) {
	label := ReconcileLabel(finalScore, c)
	confidence := Confidence(finalScore, LabelFor(finalScore), partialAnalysis, source)
	return label, confidence
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
