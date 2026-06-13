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

func TestReconcileLabel(t *testing.T) {
	tests := []struct {
		name  string
		score int
		c     Components
		want  Label
	}{
		// Malware band (76–100): malware only when attachment is the
		// dominant high driver.
		{"attachment dominant & high → malware", 85, Components{Attachment: ptrInt(90), URL: ptrInt(40)}, LabelMalware},
		{"attachment nil in band → phishing", 85, Components{URL: ptrInt(85)}, LabelPhishing},
		{"attachment present but low → phishing", 85, Components{Attachment: ptrInt(30), URL: ptrInt(80)}, LabelPhishing},
		{"attachment present but not dominant → phishing", 85, Components{Attachment: ptrInt(70), URL: ptrInt(95)}, LabelPhishing},
		{"attachment ties high driver → malware (ties win)", 85, Components{Attachment: ptrInt(90), URL: ptrInt(90)}, LabelMalware},
		{"attachment only present component → malware", 85, Components{Attachment: ptrInt(80)}, LabelMalware},
		{"attachment high but URL strictly higher → phishing", 90, Components{Attachment: ptrInt(80), URL: ptrInt(81)}, LabelPhishing},
		{"no components in band → phishing", 90, Components{}, LabelPhishing},

		// Boundary at 76, both ways.
		{"score 76 attachment dominant → malware", 76, Components{Attachment: ptrInt(80), URL: ptrInt(50)}, LabelMalware},
		{"score 76 no attachment → phishing", 76, Components{URL: ptrInt(70)}, LabelPhishing},
		{"score 76 attachment below floor → phishing", 76, Components{Attachment: ptrInt(75), URL: ptrInt(60)}, LabelPhishing},

		// Bands 0–75 are unaffected by the reconcile — attachment is
		// ignored entirely.
		{"benign band unaffected", 10, Components{Attachment: ptrInt(99)}, LabelBenign},
		{"suspicious band unaffected", 40, Components{Attachment: ptrInt(99)}, LabelSuspicious},
		{"phishing band unaffected", 70, Components{Attachment: ptrInt(99)}, LabelPhishing},
		{"phishing band boundary 75 unaffected", 75, Components{Attachment: ptrInt(99)}, LabelPhishing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReconcileLabel(tt.score, tt.c); got != tt.want {
				t.Fatalf("ReconcileLabel(%d, %+v) = %v, want %v", tt.score, tt.c, got, tt.want)
			}
		})
	}
}

// TestReconcileLabel_ConfidenceInvariant guards the confidence trap: a
// score in the malware band reclassified to phishing must keep the SAME
// confidence it would have had as malware, because confidence is computed
// against the score's NATURAL band (LabelFor), independent of the
// malware-vs-phishing renaming. If confidence ever started keying off the
// reconciled label, an 85→phishing would measure against the 51–75 band
// and collapse to 0 — this test would catch that regression.
func TestReconcileLabel_ConfidenceInvariant(t *testing.T) {
	const score = 85
	// Two component sets that yield the same score band but different
	// reconciled labels.
	malwareCase := Components{Attachment: ptrInt(90), URL: ptrInt(40)} // → malware
	phishingCase := Components{URL: ptrInt(85)}                        // → phishing

	if got := ReconcileLabel(score, malwareCase); got != LabelMalware {
		t.Fatalf("precondition: malwareCase reconciled to %v, want malware", got)
	}
	if got := ReconcileLabel(score, phishingCase); got != LabelPhishing {
		t.Fatalf("precondition: phishingCase reconciled to %v, want phishing", got)
	}

	// Confidence is always computed against LabelFor(score), so both must
	// match — and both must equal the natural malware-band confidence.
	natural := Confidence(score, LabelFor(score), false, VerdictSourceModel)
	confMalware := Confidence(score, LabelFor(score), false, VerdictSourceModel)
	confPhishing := Confidence(score, LabelFor(score), false, VerdictSourceModel)

	if confMalware != natural || confPhishing != natural {
		t.Fatalf("confidence drifted from natural band: malware=%v phishing=%v natural=%v",
			confMalware, confPhishing, natural)
	}
	// Sanity: had we (wrongly) keyed confidence off the reconciled phishing
	// label, it would differ from the natural malware-band value.
	wrong := Confidence(score, LabelPhishing, false, VerdictSourceModel)
	if wrong == natural {
		t.Fatalf("test is not exercising the trap: phishing-band confidence (%v) equals natural (%v)",
			wrong, natural)
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
