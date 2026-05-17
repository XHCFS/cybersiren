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
