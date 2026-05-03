package engine

import "math"

// Confidence implements the formula from design brief §3.7.
//
//	base = min(score - lower, upper - score) / 25
//	if partial_analysis: base *= 0.7
//	if verdict_source == "rule": base *= 0.5
//	clamp to [0, 1]
//
// Conceptually: confidence reflects label certainty, NOT severity. A
// score of 13 ("benign") has the same confidence as a score of 13 in
// the malware band would have; a score barely past a threshold is
// always low-confidence regardless of which band it lands in.
func Confidence(score int, label Label, partialAnalysis bool, source string) float64 {
	lower, upper := LabelBand(label)
	dist := math.Min(float64(score-lower), float64(upper-score))
	if dist < 0 {
		dist = 0
	}
	base := dist / 25.0

	if partialAnalysis {
		base *= 0.7
	}
	if source == VerdictSourceRule {
		base *= 0.5
	}

	if base < 0 {
		return 0
	}
	if base > 1 {
		return 1
	}
	return base
}
