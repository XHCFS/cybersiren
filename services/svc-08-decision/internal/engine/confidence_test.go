package engine

import (
	"math"
	"testing"
)

const tol = 1e-9

func TestConfidence_DesignBriefExamples(t *testing.T) {
	// Each example mirrors the worked numbers in design brief §3.7.
	tests := []struct {
		name            string
		score           int
		label           Label
		partialAnalysis bool
		source          string
		want            float64
	}{
		{"score=78 malware (lower edge)", 78, LabelMalware, false, VerdictSourceModel, 2.0 / 25.0},
		{"score=98 malware (upper edge)", 98, LabelMalware, false, VerdictSourceModel, 2.0 / 25.0},
		{"score=88 malware (centre-ish)", 88, LabelMalware, false, VerdictSourceModel, 12.0 / 25.0},
		{"score=13 benign (mid-band)", 13, LabelBenign, false, VerdictSourceModel, 12.0 / 25.0},
		{"score=88 partial penalty", 88, LabelMalware, true, VerdictSourceModel, (12.0 / 25.0) * 0.7},
		{"score=88 rule penalty", 88, LabelMalware, false, VerdictSourceRule, (12.0 / 25.0) * 0.5},
		{"score=88 both penalties", 88, LabelMalware, true, VerdictSourceRule, (12.0 / 25.0) * 0.7 * 0.5},
		{"score=0 benign edge", 0, LabelBenign, false, VerdictSourceModel, 0.0},
		{"score=100 malware edge", 100, LabelMalware, false, VerdictSourceModel, 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Confidence(tt.score, tt.label, tt.partialAnalysis, tt.source)
			if math.Abs(got-tt.want) > tol {
				t.Fatalf("Confidence(%d, %v, partial=%v, source=%q) = %v, want %v",
					tt.score, tt.label, tt.partialAnalysis, tt.source, got, tt.want)
			}
		})
	}
}

func TestConfidence_ClampedTo01(t *testing.T) {
	// Pathological band overlap → distance > 25 should still clamp to 1.0.
	// LabelMalware band is 76..100 (width 25), so the natural max is 12.5/25 = 0.5.
	// We synthesise an out-of-band score to verify the clamp.
	got := Confidence(50, LabelBenign, false, VerdictSourceModel) // 50 is outside 0..25
	if got < 0 {
		t.Fatalf("Confidence < 0: %v", got)
	}
	if got > 1 {
		t.Fatalf("Confidence > 1: %v", got)
	}
}

func TestConfidence_NegativeDistanceFloors(t *testing.T) {
	// Score below the band's lower threshold should still produce a
	// non-negative result.
	got := Confidence(80, LabelBenign, false, VerdictSourceModel)
	if got < 0 {
		t.Fatalf("Confidence(<lower) negative: %v", got)
	}
}
