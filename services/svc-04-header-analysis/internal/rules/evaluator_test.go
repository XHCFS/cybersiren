package rules

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
)

func mustLogic(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestSignalsToSnapshot_FlattensExpectedKeys(t *testing.T) {
	t.Parallel()

	domainAge := 90
	signals := header.HeaderSignals{
		Auth: header.AuthSignals{SPF: header.AuthResultFail, DKIM: header.AuthResultPass},
		Reputation: header.ReputationSignals{
			SenderDomain:      "example.com",
			IsFreeProvider:    true,
			DomainAgeDays:     &domainAge,
			TyposquatDistance: 1,
		},
		Structural: header.StructuralSignals{
			HopCount:               25,
			HopCountAboveThreshold: true,
			TimeDriftHours:         10.0,
		},
	}

	snap := SignalsToSnapshot(signals)
	if got := snap["auth.spf"]; got != "fail" {
		t.Errorf("auth.spf = %v, want fail", got)
	}
	if got := snap["reputation.is_free_provider"]; got != true {
		t.Errorf("reputation.is_free_provider should be true")
	}
	if got := snap["reputation.domain_age_days"]; got != 90 {
		t.Errorf("reputation.domain_age_days = %v, want 90", got)
	}
	if got := snap["structural.hop_count_above_threshold"]; got != true {
		t.Errorf("structural.hop_count_above_threshold should be true")
	}
}

func TestEvaluator_FiresExpectedRulesAndAggregatesScores(t *testing.T) {
	t.Parallel()

	ruleset := []CachedRule{
		{
			ID: 1, Name: "spf-fail", Version: "1.0.0", Target: "email", ScoreImpact: 30,
			Logic: mustLogic(t, map[string]any{
				"category": "auth",
				"expr":     map[string]any{"signal": "auth.spf", "op": "eq", "value": "fail"},
			}),
		},
		{
			ID: 2, Name: "ti-domain-match", Version: "1.0.0", Target: "header", ScoreImpact: 60,
			Logic: mustLogic(t, map[string]any{
				"category": "reputation",
				"expr":     map[string]any{"signal": "reputation.ti_domain_match", "op": "eq", "value": true},
			}),
		},
		{
			ID: 3, Name: "high-hop-count", Version: "1.0.0", Target: "header", ScoreImpact: 25,
			Logic: mustLogic(t, map[string]any{
				"category": "structural",
				"expr":     map[string]any{"signal": "structural.hop_count_above_threshold", "op": "eq", "value": true},
			}),
		},
		{
			// Should NOT fire (signal absent / value mismatch).
			ID: 4, Name: "free-provider", Version: "1.0.0", Target: "header", ScoreImpact: 10,
			Logic: mustLogic(t, map[string]any{
				"category": "reputation",
				"expr":     map[string]any{"signal": "reputation.is_free_provider", "op": "eq", "value": true},
			}),
		},
	}

	snap := SignalSnapshot{
		"auth.spf":                             "fail",
		"reputation.ti_domain_match":           true,
		"structural.hop_count_above_threshold": true,
		"reputation.is_free_provider":          false,
	}

	ev := NewEvaluator(zerolog.Nop())
	got := ev.Evaluate(ruleset, snap)
	if len(got.Fired) != 3 {
		t.Fatalf("expected 3 fired rules, got %d (%v)", len(got.Fired), got.Fired)
	}
	if got.AuthSubScore != 30 {
		t.Errorf("auth sub-score = %d, want 30", got.AuthSubScore)
	}
	if got.ReputationSubScore != 60 {
		t.Errorf("reputation sub-score = %d, want 60", got.ReputationSubScore)
	}
	if got.StructuralSubScore != 25 {
		t.Errorf("structural sub-score = %d, want 25", got.StructuralSubScore)
	}
}

func TestEvaluator_MalformedRulesAreSkipped(t *testing.T) {
	t.Parallel()

	ruleset := []CachedRule{
		{ID: 1, Name: "good", Version: "1.0.0", Target: "header", ScoreImpact: 50,
			Logic: mustLogic(t, map[string]any{"signal": "x", "op": "eq", "value": 1})},
		{ID: 2, Name: "broken-json", Version: "1.0.0", Target: "header", ScoreImpact: 99,
			Logic: json.RawMessage([]byte("not-json"))},
	}

	ev := NewEvaluator(zerolog.Nop())
	got := ev.Evaluate(ruleset, SignalSnapshot{"x": 1})
	if len(got.Fired) != 1 || got.Fired[0].Rule.ID != 1 {
		t.Errorf("expected only good rule to fire, got %+v", got.Fired)
	}
}

func TestEvaluator_SubScoresClampedTo100(t *testing.T) {
	t.Parallel()

	ruleset := []CachedRule{
		{ID: 1, Name: "a", Version: "1.0.0", Target: "header", ScoreImpact: 80,
			Logic: mustLogic(t, map[string]any{"category": "structural",
				"expr": map[string]any{"signal": "x", "op": "exists"}})},
		{ID: 2, Name: "b", Version: "1.0.0", Target: "header", ScoreImpact: 80,
			Logic: mustLogic(t, map[string]any{"category": "structural",
				"expr": map[string]any{"signal": "x", "op": "exists"}})},
	}
	ev := NewEvaluator(zerolog.Nop())
	got := ev.Evaluate(ruleset, SignalSnapshot{"x": "any"})
	if got.StructuralSubScore != 100 {
		t.Errorf("expected clamp to 100, got %d", got.StructuralSubScore)
	}
}

func TestFinalScore(t *testing.T) {
	t.Parallel()

	if got := FinalScore(20, 60, 40, "max"); got != 60 {
		t.Errorf("max = %d, want 60", got)
	}
	if got := FinalScore(30, 60, 90, "average"); got != 60 {
		t.Errorf("average = %d, want 60", got)
	}
	// Weighted: weights 1,2,1 → (30*1 + 60*2 + 90*1) / 4 = 60
	if got := FinalScore(30, 60, 90, "weighted", 1, 2, 1); got != 60 {
		t.Errorf("weighted = %d, want 60", got)
	}
	// Weighted with all-zero weights falls back to equal weights.
	if got := FinalScore(30, 60, 90, "weighted", 0, 0, 0); got != 60 {
		t.Errorf("weighted (zero) = %d, want 60", got)
	}
	// Unknown blend falls back to max.
	if got := FinalScore(10, 20, 30, "potato"); got != 30 {
		t.Errorf("unknown blend should fall back to max; got %d", got)
	}
}
