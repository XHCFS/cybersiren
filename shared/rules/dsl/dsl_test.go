package dsl

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestEvaluate_LeafConditions(t *testing.T) {
	t.Parallel()

	snap := SignalSnapshot{
		"auth.spf":                    "fail",
		"auth.from_reply_to_match":    false,
		"structural.hop_count":        20,
		"reputation.is_free_provider": true,
	}

	tests := []struct {
		name  string
		logic any
		want  bool
	}{
		{
			name:  "eq match",
			logic: map[string]any{"signal": "auth.spf", "op": "eq", "value": "fail"},
			want:  true,
		},
		{
			name:  "eq case-insensitive on string",
			logic: map[string]any{"signal": "auth.spf", "op": "eq", "value": "FAIL"},
			want:  true,
		},
		{
			name:  "neq false when equal",
			logic: map[string]any{"signal": "auth.spf", "op": "neq", "value": "fail"},
			want:  false,
		},
		{
			name:  "gt true",
			logic: map[string]any{"signal": "structural.hop_count", "op": "gt", "value": 15},
			want:  true,
		},
		{
			name:  "gte boundary",
			logic: map[string]any{"signal": "structural.hop_count", "op": "gte", "value": 20},
			want:  true,
		},
		{
			name:  "lt false",
			logic: map[string]any{"signal": "structural.hop_count", "op": "lt", "value": 15},
			want:  false,
		},
		{
			name:  "in",
			logic: map[string]any{"signal": "auth.spf", "op": "in", "value": []string{"fail", "softfail"}},
			want:  true,
		},
		{
			name:  "not_in",
			logic: map[string]any{"signal": "auth.spf", "op": "not_in", "value": []string{"pass"}},
			want:  true,
		},
		{
			name:  "exists",
			logic: map[string]any{"signal": "structural.hop_count", "op": "exists"},
			want:  true,
		},
		{
			name:  "missing",
			logic: map[string]any{"signal": "auth.dmarc", "op": "missing"},
			want:  true,
		},
		{
			name:  "boolean eq",
			logic: map[string]any{"signal": "reputation.is_free_provider", "op": "eq", "value": true},
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Evaluate(mustJSON(t, tc.logic), snap)
			if err != nil {
				t.Fatalf("Evaluate err = %v", err)
			}
			if r.Matched != tc.want {
				t.Errorf("Matched = %v, want %v (detail=%v)", r.Matched, tc.want, r.Detail)
			}
		})
	}
}

func TestEvaluate_Composite(t *testing.T) {
	t.Parallel()

	snap := SignalSnapshot{
		"auth.spf":   "fail",
		"auth.dmarc": "fail",
		"hops":       3,
	}

	allLogic := map[string]any{
		"all": []any{
			map[string]any{"signal": "auth.spf", "op": "eq", "value": "fail"},
			map[string]any{"signal": "auth.dmarc", "op": "eq", "value": "fail"},
		},
	}
	if r, err := Evaluate(mustJSON(t, allLogic), snap); err != nil || !r.Matched {
		t.Fatalf("expected ALL to match, got matched=%v err=%v", r.Matched, err)
	}

	anyLogic := map[string]any{
		"any": []any{
			map[string]any{"signal": "auth.spf", "op": "eq", "value": "pass"},
			map[string]any{"signal": "auth.dmarc", "op": "eq", "value": "fail"},
		},
	}
	if r, err := Evaluate(mustJSON(t, anyLogic), snap); err != nil || !r.Matched {
		t.Fatalf("expected ANY to match, got matched=%v err=%v", r.Matched, err)
	}

	notLogic := map[string]any{
		"not": map[string]any{"signal": "auth.spf", "op": "eq", "value": "pass"},
	}
	if r, err := Evaluate(mustJSON(t, notLogic), snap); err != nil || !r.Matched {
		t.Fatalf("expected NOT to match, got matched=%v err=%v", r.Matched, err)
	}
}

func TestEvaluate_CategoryDeclaration(t *testing.T) {
	t.Parallel()

	snap := SignalSnapshot{"reputation.ti_domain_match": true}

	logic := map[string]any{
		"category": "reputation",
		"expr":     map[string]any{"signal": "reputation.ti_domain_match", "op": "eq", "value": true},
	}
	r, err := Evaluate(mustJSON(t, logic), snap)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !r.Matched || r.Category != CategoryReputation {
		t.Errorf("expected reputation category match, got %+v", r)
	}
}

func TestEvaluate_MalformedRulesReturnError(t *testing.T) {
	t.Parallel()

	cases := []json.RawMessage{
		nil,
		[]byte(""),
		[]byte("not json"),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`{"signal":"x"}`),
		[]byte(`{"signal":"x","op":"unknown"}`),
		[]byte(`{"category":"auth"}`),
	}

	snap := SignalSnapshot{"x": 1}
	for i, c := range cases {
		i, c := i, c
		t.Run("", func(t *testing.T) {
			t.Parallel()
			r, err := Evaluate(c, snap)
			if err == nil && r.Matched {
				t.Fatalf("case %d: expected error or no-match, got %+v", i, r)
			}
		})
	}
}

func TestEvaluate_UnknownSignalIsNotAMatch(t *testing.T) {
	t.Parallel()

	logic := map[string]any{"signal": "not.in.snapshot", "op": "eq", "value": "x"}
	snap := SignalSnapshot{}
	r, err := Evaluate(mustJSON(t, logic), snap)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.Matched {
		t.Errorf("unknown signal must not match, got %+v", r)
	}
}
