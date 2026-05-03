package engine

import (
	"math"
	"testing"
)

func ptrInt(v int) *int { return &v }

func TestWeightedAverageBlender_AllComponents(t *testing.T) {
	// Default weights: 0.35 / 0.30 / 0.25 / 0.10. Sum = 1.0.
	b := NewWeightedAverageBlender(DefaultWeights())
	out := b.Blend(Components{
		URL:        ptrInt(80),
		Header:     ptrInt(60),
		NLP:        ptrInt(40),
		Attachment: ptrInt(20),
	})

	want := 0.35*80 + 0.30*60 + 0.25*40 + 0.10*20 // = 58.0
	if math.Abs(out.Score-want) > 1e-9 {
		t.Fatalf("Blend(): score=%v, want %v", out.Score, want)
	}
	if math.Abs(out.WeightSum-1.0) > 1e-9 {
		t.Fatalf("Blend(): weight sum=%v, want 1.0", out.WeightSum)
	}
	// Contributions must sum back to the blended score.
	var sum float64
	for _, v := range out.Contributions {
		sum += v
	}
	if math.Abs(sum-out.Score) > 1e-6 {
		t.Fatalf("Blend(): contributions sum=%v, want %v", sum, out.Score)
	}
}

func TestWeightedAverageBlender_PartialAnalysis(t *testing.T) {
	// Only URL + header are present; the denominator must be 0.35 + 0.30 = 0.65.
	b := NewWeightedAverageBlender(DefaultWeights())
	out := b.Blend(Components{URL: ptrInt(80), Header: ptrInt(60)})

	want := (0.35*80 + 0.30*60) / 0.65 // ≈ 70.769...
	if math.Abs(out.Score-want) > 1e-9 {
		t.Fatalf("partial blend: score=%v, want %v", out.Score, want)
	}
	if math.Abs(out.WeightSum-0.65) > 1e-9 {
		t.Fatalf("partial blend: weight sum=%v, want 0.65", out.WeightSum)
	}
}

func TestWeightedAverageBlender_NoComponents(t *testing.T) {
	b := NewWeightedAverageBlender(DefaultWeights())
	out := b.Blend(Components{})
	if out.Score != 0 {
		t.Fatalf("empty blend: score=%v, want 0", out.Score)
	}
	if out.WeightSum != 0 {
		t.Fatalf("empty blend: weight sum=%v, want 0", out.WeightSum)
	}
}

func TestWeightedAverageBlender_ClampedToRange(t *testing.T) {
	// Weights with sum ≤ 0 should fall back to defaults.
	b := NewWeightedAverageBlender(BlendWeights{})
	out := b.Blend(Components{URL: ptrInt(150)}) // upstream guard, but defensive
	if out.Score < 0 || out.Score > 100 {
		t.Fatalf("blended score out of [0,100]: got %v", out.Score)
	}
}

func TestComponents_HasAnyML(t *testing.T) {
	tests := []struct {
		name string
		in   Components
		want bool
	}{
		{"empty", Components{}, false},
		{"attachment only", Components{Attachment: ptrInt(50)}, false},
		{"url present", Components{URL: ptrInt(50)}, true},
		{"header present", Components{Header: ptrInt(50)}, true},
		{"nlp present", Components{NLP: ptrInt(50)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.HasAnyML(); got != tt.want {
				t.Fatalf("HasAnyML() = %v, want %v", got, tt.want)
			}
		})
	}
}
