package campaign

import (
	"math"
	"testing"
)

func TestNudge_NoCampaign_PassesThrough(t *testing.T) {
	got, alpha := Nudge(60, nil, DefaultShrinkage())
	if got != 60 || alpha != 0 {
		t.Fatalf("Nudge(nil) = (%v, %v), want (60, 0)", got, alpha)
	}
}

func TestNudge_ZeroEmailCount_PassesThrough(t *testing.T) {
	got, alpha := Nudge(40, &History{RiskScore: 90, EmailCount: 0}, DefaultShrinkage())
	if got != 40 || alpha != 0 {
		t.Fatalf("Nudge(empty campaign) = (%v, %v), want (40, 0)", got, alpha)
	}
}

func TestNudge_AlphaCappedByAlphaMax(t *testing.T) {
	cfg := DefaultShrinkage() // AlphaMax = 0.30
	// With n=10000 and tau=5, n/(n+tau) ≈ 0.9995 ≫ AlphaMax — capped to 0.30.
	got, alpha := Nudge(40, &History{RiskScore: 100, EmailCount: 10_000}, cfg)
	if math.Abs(alpha-0.30) > 1e-9 {
		t.Fatalf("alpha=%v, want 0.30", alpha)
	}
	want := 0.70*40 + 0.30*100 // = 46
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("nudged score = %v, want %v", got, want)
	}
}

func TestNudge_AlphaBelowCap(t *testing.T) {
	cfg := Shrinkage{Tau: 5, AlphaMax: 0.30}
	// n=5, tau=5 → alpha = 5/(5+5) = 0.50. But AlphaMax = 0.30 caps it.
	// Use a smaller n to land below the cap: n=1, tau=5 → 1/6 ≈ 0.1667.
	_, alpha := Nudge(40, &History{RiskScore: 100, EmailCount: 1}, cfg)
	want := 1.0 / 6.0
	if math.Abs(alpha-want) > 1e-9 {
		t.Fatalf("alpha=%v, want %v", alpha, want)
	}
}

func TestNudge_ScoreClampedToRange(t *testing.T) {
	got, _ := Nudge(-10, &History{RiskScore: 50, EmailCount: 100}, DefaultShrinkage())
	if got < 0 {
		t.Fatalf("nudged score < 0: %v", got)
	}
	got, _ = Nudge(120, &History{RiskScore: 50, EmailCount: 100}, DefaultShrinkage())
	if got > 100 {
		t.Fatalf("nudged score > 100: %v", got)
	}
}

func TestNudge_EmailScoreAboveCampaignMean_PullsDown(t *testing.T) {
	// Email score 80, campaign average 50, n=20 → α capped at 0.30.
	got, _ := Nudge(80, &History{RiskScore: 50, EmailCount: 20}, DefaultShrinkage())
	want := 0.70*80 + 0.30*50 // = 71
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("got=%v, want %v", got, want)
	}
}
