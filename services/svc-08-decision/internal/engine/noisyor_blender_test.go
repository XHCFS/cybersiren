package engine

import (
	"math"
	"testing"
)

func iptr(v int) *int { return &v }

// blendScore is a tiny helper: build the noisy-OR blender with default
// reliabilities and return the rounded fused score for the given components.
func blendScore(t *testing.T, c Components) int {
	t.Helper()
	b := NewReliabilityNoisyORBlender(DefaultReliabilities())
	return Round(b.Blend(c).Score)
}

// TestNoisyOR_NoDilution is the core fix: a confident channel must NOT be pulled
// below threshold by clean channels (the weighted-average bug).
func TestNoisyOR_NoDilution(t *testing.T) {
	// text-only BEC: NLP=100, header clean. Weighted average gives 45 (missed);
	// noisy-OR must keep it high.
	got := blendScore(t, Components{NLP: iptr(100), Header: iptr(0)})
	if got <= 50 {
		t.Fatalf("text-only threat diluted by clean header: got %d, want > 50", got)
	}
	// header-only spoof: header high, text clean — must still fire.
	got = blendScore(t, Components{NLP: iptr(3), Header: iptr(88)})
	if got <= 50 {
		t.Fatalf("header-only threat not caught: got %d, want > 50", got)
	}
}

// TestNoisyOR_AdversarialBattery encodes the fusion decisions that separate a
// good aggregator from a bad one. Phishing must clear 50; legit must stay under.
func TestNoisyOR_AdversarialBattery(t *testing.T) {
	cases := []struct {
		name  string
		c     Components
		phish bool
	}{
		{"text-only phish (BEC)", Components{NLP: iptr(92), Header: iptr(5)}, true},
		{"header-only phish", Components{NLP: iptr(3), Header: iptr(88)}, true},
		{"multi-channel phish", Components{NLP: iptr(85), URL: iptr(90), Header: iptr(80)}, true},
		{"soft multi-channel", Components{NLP: iptr(55), Header: iptr(60)}, true},
		{"malicious attachment alone", Components{NLP: iptr(5), Attachment: iptr(95)}, true},
		// legit traps — must NOT fire:
		{"legit + one noisy url", Components{NLP: iptr(3), URL: iptr(92), Header: iptr(3)}, false},
		{"legit + many noisy urls (max~97)", Components{NLP: iptr(4), URL: iptr(97), Header: iptr(3)}, false},
		{"legit forwarded (header 45)", Components{NLP: iptr(3), Header: iptr(45)}, false},
		{"legit security-notice text (nlp 35)", Components{NLP: iptr(35), Header: iptr(3)}, false},
		{"all clean", Components{NLP: iptr(3), URL: iptr(2), Header: iptr(2)}, false},
	}
	for _, tc := range cases {
		got := blendScore(t, tc.c)
		fired := got > 50
		if fired != tc.phish {
			t.Errorf("%s: score=%d fired=%v, want phish=%v", tc.name, got, fired, tc.phish)
		}
	}
}

// TestNoisyOR_URLDistrust documents the structural distrust of the lexical URL
// channel: a high URL score ALONE must not clear threshold (it defers to SVC-03),
// but URL corroborated by another channel must.
func TestNoisyOR_URLDistrust(t *testing.T) {
	alone := blendScore(t, Components{NLP: iptr(0), URL: iptr(95), Header: iptr(0)})
	if alone > 50 {
		t.Fatalf("uncorroborated URL should defer (<=50), got %d", alone)
	}
	corroborated := blendScore(t, Components{NLP: iptr(0), URL: iptr(95), Header: iptr(80)})
	if corroborated <= 50 {
		t.Fatalf("corroborated URL should fire (>50), got %d", corroborated)
	}
}

// TestNoisyOR_MissingComponents: a nil component is simply absent from the
// product; the blender must not panic or divide by zero, and an all-nil input
// yields 0.
func TestNoisyOR_MissingComponents(t *testing.T) {
	// only NLP present
	if got := blendScore(t, Components{NLP: iptr(90)}); got <= 50 {
		t.Fatalf("NLP-only high score should fire, got %d", got)
	}
	// nothing present
	b := NewReliabilityNoisyORBlender(DefaultReliabilities())
	res := b.Blend(Components{})
	if res.Score != 0 || res.WeightSum != 0 {
		t.Fatalf("empty components: got score=%v weightSum=%v, want 0/0", res.Score, res.WeightSum)
	}
}

// TestNoisyOR_FloorAndMonotonicity checks two provable properties: the fused
// score is >= the strongest single-channel contribution (no dilution floor), and
// raising any component score never lowers the result.
func TestNoisyOR_FloorAndMonotonicity(t *testing.T) {
	b := NewReliabilityNoisyORBlender(DefaultReliabilities())
	// floor: risk >= 100 * max_c (r_c * s_c/100). With NLP=70 (r=1.0) the floor is 70.
	res := b.Blend(Components{NLP: iptr(70), URL: iptr(10), Header: iptr(10)})
	if res.Score < 70-1e-9 {
		t.Fatalf("floor violated: score %v < 70", res.Score)
	}
	// monotonicity: increasing header never lowers the score.
	prev := math.Inf(-1)
	for h := 0; h <= 100; h += 10 {
		s := b.Blend(Components{NLP: iptr(40), Header: iptr(h)}).Score
		if s < prev-1e-9 {
			t.Fatalf("non-monotonic: header=%d gave %v < previous %v", h, s, prev)
		}
		prev = s
	}
}

// TestNoisyOR_DefaultsGuard: an all-zero reliability set must fall back to
// defaults rather than producing an always-benign blender.
func TestNoisyOR_DefaultsGuard(t *testing.T) {
	b := NewReliabilityNoisyORBlender(Reliabilities{})
	if got := Round(b.Blend(Components{NLP: iptr(95)}).Score); got <= 50 {
		t.Fatalf("zero-reliability config should fall back to defaults, got %d", got)
	}
}

// TestSelectBlender wires the config switch: noisy_or selects the noisy-OR,
// everything else (incl. empty) selects the weighted average.
func TestSelectBlender(t *testing.T) {
	if _, ok := selectBlender(Config{FusionMode: FusionNoisyOR}.Defaults()).(*ReliabilityNoisyORBlender); !ok {
		t.Fatal("FusionNoisyOR did not select the noisy-OR blender")
	}
	if _, ok := selectBlender(Config{FusionMode: FusionWeightedAverage}.Defaults()).(*WeightedAverageBlender); !ok {
		t.Fatal("FusionWeightedAverage did not select the weighted-average blender")
	}
	if _, ok := selectBlender(Config{FusionMode: "bogus"}.Defaults()).(*WeightedAverageBlender); !ok {
		t.Fatal("unknown fusion mode should fall back to weighted average")
	}
}
