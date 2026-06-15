package engine

import (
	"math"
	"testing"
)

func iptr(v int) *int { return &v }

func noisyOR() *ReliabilityNoisyORBlender {
	return NewReliabilityNoisyORBlender(DefaultReliabilities())
}
func blendScore(c Components) int  { return Round(noisyOR().Blend(c).Score) }
func blendBand(c Components) Label { return LabelFor(blendScore(c)) }

// TestNoisyOR_ConfirmedSignalsSurvive is the regression test for review B1/B2:
// a single CONFIRMED channel that SVC-03/05 pinned to a high score must reach the
// high band — the OR-floor (risk >= max score at reliability 1.0) guarantees it.
// The old weighted average DILUTED these (a TI-confirmed URL with clean text
// scored ~28-41 -> "suspicious"); the OR keeps them in the malware (76-100) band.
//
// NOTE: this asserts the BLENDER's natural band (LabelFor). The engine then applies
// ReconcileLabel, which keeps the malware label only when a malware-grade attachment
// is present and otherwise emits phishing(high) — so the URL-only cases below surface
// to the operator as phishing(high), the attachment cases as malware. The point this
// test pins is that none are diluted out of the high band, not the final label name.
func TestNoisyOR_ConfirmedSignalsSurvive(t *testing.T) {
	cases := []struct {
		name string
		c    Components
	}{
		{"TI/guard URL=100 alone", Components{URL: iptr(100)}},
		{"TI URL=100 + clean text + clean header", Components{URL: iptr(100), NLP: iptr(3), Header: iptr(3)}},
		{"confirmed-malware attachment=95 alone", Components{Attachment: iptr(95)}},
		{"confirmed-malware attachment=90 + clean text", Components{Attachment: iptr(90), NLP: iptr(3)}},
	}
	for _, tc := range cases {
		score := blendScore(tc.c)
		if score < 90 {
			t.Errorf("%s: confirmed signal diluted to %d (want >= its pinned score)", tc.name, score)
		}
		if band := LabelFor(score); band != LabelMalware {
			t.Errorf("%s: band %q, want %q (score=%d)", tc.name, band, LabelMalware, score)
		}
	}
}

// TestNoisyOR_NoDilution: a confident channel is never pulled below threshold by
// clean channels (the core defect of the weighted average).
func TestNoisyOR_NoDilution(t *testing.T) {
	// text-only BEC: NLP=100, clean header. Weighted average -> 45 (missed).
	if got := blendScore(Components{NLP: iptr(100), Header: iptr(0)}); got < 100 {
		t.Fatalf("text-only threat diluted by clean header: got %d, want 100", got)
	}
	// header-only spoof.
	if got := blendScore(Components{NLP: iptr(3), Header: iptr(88)}); got <= 50 {
		t.Fatalf("header-only threat not caught: got %d", got)
	}
}

// TestNoisyOR_FourBandCharacterization PINS the verdict band for representative
// inputs. The probabilistic OR shifts the score distribution UP relative to the
// weighted mean; this table makes that shift explicit (it is the input for the
// §3.6 band recalibration that gates enabling this mode by default). If a value
// changes, this test fails on purpose so the distribution change is reviewed.
func TestNoisyOR_FourBandCharacterization(t *testing.T) {
	cases := []struct {
		name string
		c    Components
		want Label
	}{
		// clearly legit -> low bands
		{"all clean", Components{NLP: iptr(3), URL: iptr(2), Header: iptr(2)}, LabelBenign},
		{"legit forwarded (header 45)", Components{NLP: iptr(3), Header: iptr(45)}, LabelSuspicious},
		{"single moderate channel (nlp 40)", Components{NLP: iptr(40)}, LabelSuspicious},
		// the OR's known up-shift: two correlated moderate signals reach phishing.
		// Documented, not endorsed — see the independence caveat in §3.4.
		{"two moderate channels (nlp 40 + header 40)", Components{NLP: iptr(40), Header: iptr(40)}, LabelPhishing},
		// confirmed / strong -> malware band
		{"confirmed URL=100", Components{URL: iptr(100)}, LabelMalware},
		{"strong multi-channel", Components{NLP: iptr(85), URL: iptr(90), Header: iptr(80)}, LabelMalware},
	}
	for _, tc := range cases {
		if got := blendBand(tc.c); got != tc.want {
			t.Errorf("%s: band %q, want %q (score=%d)", tc.name, got, tc.want, blendScore(tc.c))
		}
	}
}

// TestNoisyOR_FloorAndMonotonicity: provable properties.
func TestNoisyOR_FloorAndMonotonicity(t *testing.T) {
	b := noisyOR()
	// OR-floor: risk >= max single-channel contribution (= max score at rel 1.0).
	res := b.Blend(Components{NLP: iptr(70), URL: iptr(10), Header: iptr(10)})
	if res.Score < 70-1e-9 {
		t.Fatalf("floor violated: score %v < 70", res.Score)
	}
	// monotone: raising a component never lowers the score.
	prev := math.Inf(-1)
	for h := 0; h <= 100; h += 10 {
		s := b.Blend(Components{NLP: iptr(40), Header: iptr(h)}).Score
		if s < prev-1e-9 {
			t.Fatalf("non-monotonic: header=%d gave %v < previous %v", h, s, prev)
		}
		prev = s
	}
}

// TestNoisyOR_MissingComponents: nil components are absent from the product; an
// all-nil input yields 0 without panicking or dividing by zero.
func TestNoisyOR_MissingComponents(t *testing.T) {
	if got := blendScore(Components{NLP: iptr(90)}); got < 90 {
		t.Fatalf("NLP-only high score should reach 90, got %d", got)
	}
	res := noisyOR().Blend(Components{})
	if res.Score != 0 || res.WeightSum != 0 {
		t.Fatalf("empty components: got score=%v weightSum=%v, want 0/0", res.Score, res.WeightSum)
	}
}

// TestNoisyOR_DefaultsGuard: an all-zero reliability set falls back to defaults.
func TestNoisyOR_DefaultsGuard(t *testing.T) {
	b := NewReliabilityNoisyORBlender(Reliabilities{})
	if got := Round(b.Blend(Components{NLP: iptr(95)}).Score); got < 90 {
		t.Fatalf("zero-reliability config should fall back to defaults, got %d", got)
	}
}

// TestBuildBlenders wires the config switch: the active blender matches the mode
// and the shadow is always the *other* method. Unknown modes fall back to the
// weighted average as the active method.
func TestBuildBlenders(t *testing.T) {
	active, shadow := buildBlenders(Config{FusionMode: FusionNoisyOR}.Defaults())
	if _, ok := active.(*ReliabilityNoisyORBlender); !ok {
		t.Fatal("FusionNoisyOR did not select the noisy-OR blender")
	}
	if _, ok := shadow.(*WeightedAverageBlender); !ok {
		t.Fatal("with noisy_or active, shadow should be the weighted average")
	}

	active, shadow = buildBlenders(Config{FusionMode: FusionWeightedAverage}.Defaults())
	if _, ok := active.(*WeightedAverageBlender); !ok {
		t.Fatal("FusionWeightedAverage did not select the weighted-average blender")
	}
	if _, ok := shadow.(*ReliabilityNoisyORBlender); !ok {
		t.Fatal("with weighted_average active, shadow should be the noisy-OR")
	}

	active, _ = buildBlenders(Config{FusionMode: "bogus"}.Defaults())
	if _, ok := active.(*WeightedAverageBlender); !ok {
		t.Fatal("unknown fusion mode should fall back to weighted average")
	}
}
