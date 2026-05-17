package engine

import "testing"

func TestLabelFor_Boundaries(t *testing.T) {
	tests := []struct {
		score int
		want  Label
	}{
		{0, LabelBenign},
		{25, LabelBenign},
		{26, LabelSuspicious},
		{50, LabelSuspicious},
		{51, LabelPhishing},
		{75, LabelPhishing},
		{76, LabelMalware},
		{100, LabelMalware},
	}
	for _, tt := range tests {
		if got := LabelFor(tt.score); got != tt.want {
			t.Errorf("LabelFor(%d) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestLabelBand_RoundTrip(t *testing.T) {
	// Picking the lower bound of a band must always map back to the
	// same label.
	for _, lab := range []Label{LabelBenign, LabelSuspicious, LabelPhishing, LabelMalware} {
		lo, hi := LabelBand(lab)
		if got := LabelFor(lo); got != lab {
			t.Errorf("LabelFor(lower=%d) = %v, want %v", lo, got, lab)
		}
		if got := LabelFor(hi); got != lab {
			t.Errorf("LabelFor(upper=%d) = %v, want %v", hi, got, lab)
		}
	}
}

func TestSourceFor(t *testing.T) {
	tests := []struct {
		name string
		c    Components
		want string
	}{
		{"empty → rule", Components{}, VerdictSourceRule},
		{"attachment-only → rule", Components{Attachment: ptrInt(50)}, VerdictSourceRule},
		{"url → model", Components{URL: ptrInt(50)}, VerdictSourceModel},
		{"header → model", Components{Header: ptrInt(50)}, VerdictSourceModel},
		{"nlp → model", Components{NLP: ptrInt(50)}, VerdictSourceModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SourceFor(tt.c); got != tt.want {
				t.Fatalf("SourceFor() = %v, want %v", got, tt.want)
			}
		})
	}
}
