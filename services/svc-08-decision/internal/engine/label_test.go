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
		// Malware band (76–100): malware whenever a high (≥76) attachment is
		// present. ReconcileLabel never COMPARES components — the other scores'
		// magnitudes are irrelevant; only "is the attachment ≥ the floor" matters.
		// The cases below set non-attachment components purely to prove they are
		// ignored, not because they participate in a comparison.
		{"high attachment → malware", 85, Components{Attachment: ptrInt(90), URL: ptrInt(40)}, LabelMalware},
		{"attachment nil in band → phishing", 85, Components{URL: ptrInt(85)}, LabelPhishing},
		{"attachment present but below floor → phishing", 85, Components{Attachment: ptrInt(30), URL: ptrInt(80)}, LabelPhishing},
		{"attachment just below floor (75) → phishing", 85, Components{Attachment: ptrInt(75), URL: ptrInt(95)}, LabelPhishing},
		{"high attachment, larger URL ignored → malware", 90, Components{Attachment: ptrInt(80), URL: ptrInt(95)}, LabelMalware},
		{"high attachment, larger NLP/Header ignored → malware (smoke case)", 80, Components{Attachment: ptrInt(90), NLP: ptrInt(100), Header: ptrInt(60)}, LabelMalware},
		{"high attachment, equal URL ignored → malware", 85, Components{Attachment: ptrInt(90), URL: ptrInt(90)}, LabelMalware},
		{"attachment only present component → malware", 85, Components{Attachment: ptrInt(80)}, LabelMalware},
		{"attachment at floor (76), larger URL ignored → malware", 85, Components{Attachment: ptrInt(76), URL: ptrInt(99)}, LabelMalware},
		{"no components in band → phishing", 90, Components{}, LabelPhishing},

		// Boundary at 76, both ways.
		{"score 76 high attachment → malware", 76, Components{Attachment: ptrInt(80), URL: ptrInt(50)}, LabelMalware},
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

// TestVerdictLabelAndConfidence_ConfidenceTrap guards the confidence trap
// at the EXACT production seam both Handle and publishDegraded call:
// verdictLabelAndConfidence. A malware-band score reclassified to phishing
// must keep the confidence of its NATURAL (76–100) band, because confidence
// is computed against LabelFor(score), not the reconciled label.
//
// This is not a tautology: it derives the "buggy" value from the reconciled
// label and asserts the helper does NOT use it. Were a future edit to thread
// the reconciled label into Confidence (the regression the brief warns
// about), the phishing case below would collapse from the natural band value
// to the 51–75-band value and these assertions would fail.
func TestVerdictLabelAndConfidence_ConfidenceTrap(t *testing.T) {
	const score = 85

	// A high-band component set whose reconciled label is phishing(high)
	// (URL-driven, no dominant attachment) and one whose reconciled label is
	// malware (attachment-dominant). The trap only bites the phishing case.
	phishingCase := Components{URL: ptrInt(85)}                        // → phishing(high)
	malwareCase := Components{Attachment: ptrInt(90), URL: ptrInt(40)} // → malware

	// The natural-band confidence the helper MUST return regardless of the
	// reconciled label, and the collapsed value the buggy wiring WOULD return
	// for the phishing case. They must differ, or the test proves nothing.
	natural := Confidence(score, LabelFor(score), false, VerdictSourceModel)
	buggyCollapsed := Confidence(score, LabelPhishing, false, VerdictSourceModel)
	if natural == buggyCollapsed {
		t.Fatalf("test cannot exercise the trap: natural-band confidence (%v) equals "+
			"the reconciled-phishing-band value (%v)", natural, buggyCollapsed)
	}

	gotPhishLabel, gotPhishConf := verdictLabelAndConfidence(score, phishingCase, false, VerdictSourceModel)
	if gotPhishLabel != LabelPhishing {
		t.Fatalf("phishing case: label = %v, want phishing", gotPhishLabel)
	}
	if gotPhishConf != natural {
		t.Fatalf("CONFIDENCE TRAP: phishing-reconciled label collapsed confidence to %v; "+
			"must stay at the natural malware-band value %v (got the buggy %v? %t)",
			gotPhishConf, natural, buggyCollapsed, gotPhishConf == buggyCollapsed)
	}

	gotMalLabel, gotMalConf := verdictLabelAndConfidence(score, malwareCase, false, VerdictSourceModel)
	if gotMalLabel != LabelMalware {
		t.Fatalf("malware case: label = %v, want malware", gotMalLabel)
	}
	if gotMalConf != natural {
		t.Fatalf("malware case: confidence = %v, want natural-band %v", gotMalConf, natural)
	}

	// The whole point: labels differ (malware vs phishing) yet confidences are
	// identical — the reconcile renames the label without perturbing confidence.
	if gotPhishConf != gotMalConf {
		t.Fatalf("confidence must be label-independent: phishing=%v malware=%v",
			gotPhishConf, gotMalConf)
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
