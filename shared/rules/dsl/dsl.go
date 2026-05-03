// Package dsl is the shared JSON-DSL interpreter used by every service
// that evaluates entries in the rules table (SVC-04 Header Analysis and
// SVC-08 Decision Engine today; future analysers will reuse it as well).
//
// The DSL itself is unchanged from its original SVC-04 home; this
// package was extracted so SVC-08 — which lives outside SVC-04's
// `internal/` import boundary — can reuse the same interpreter rather
// than reimplementing it. See ARCH-SPEC §6 and the design brief in
// docs/design/svc-07-08-design-brief.md §4.2.
//
// DSL design
// ----------------------------------------------------------------------------
// rules.logic is a JSONB column. Services need to evaluate it against a
// flat snapshot of signals. To keep the surface area small while still
// being expressive enough for the seed rules, we accept this minimal
// grammar:
//
//	leaf-condition (most common):
//	  {"signal": "auth.spf",       "op": "eq",  "value": "fail"}
//	  {"signal": "structural.hop_count", "op": "gt", "value": 15}
//	  {"signal": "reputation.ti_domain_match", "op": "eq", "value": true}
//	  {"signal": "auth.from_reply_to_match", "op": "eq", "value": false}
//	  {"signal": "auth.spf", "op": "in", "value": ["fail", "softfail"]}
//
//	composite:
//	  {"all": [<expr>, <expr>, ...]}   // logical AND
//	  {"any": [<expr>, <expr>, ...]}   // logical OR
//	  {"not": <expr>}                  // logical NOT
//
//	category (so a rule can declare which sub-score it contributes to):
//	  {"category": "auth"|"reputation"|"structural", "expr": <expr>}
//
// Recognised signal identifiers are owned by each consumer (SVC-04 has
// a header-signals list, SVC-08 publishes its own snapshot keys).
// Unknown signals or operators short-circuit to "no match" — we do NOT
// throw, in line with ARCH-SPEC §6 ("skip malformed rule, log,
// continue").
//
// The interpreter is pure / stateless: tests can drive it directly.
package dsl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Category is the sub-score bucket a rule contributes to. SVC-04 uses
// the three header categories below; other services that don't carry
// sub-scores (SVC-08) ignore the category entirely.
type Category string

const (
	CategoryAuth       Category = "auth"
	CategoryReputation Category = "reputation"
	CategoryStructural Category = "structural"
)

// SignalSnapshot is the flat, pure value bag the DSL evaluates against.
// Keys are stable — they are part of the rule contract and may be
// referenced from rules.logic.
type SignalSnapshot map[string]any

// MatchResult represents the output of a single rule evaluation.
type MatchResult struct {
	Matched  bool
	Category Category
	Detail   map[string]any
}

// Evaluate returns the match result for a single rules.logic blob.
//
// Errors are returned for *malformed* rule blobs (so the caller can
// observe and skip them). A non-error, non-matched result is the
// happy-path "rule didn't fire".
func Evaluate(logic json.RawMessage, signals SignalSnapshot) (MatchResult, error) {
	if len(logic) == 0 {
		return MatchResult{}, errors.New("rule logic is empty")
	}

	root := map[string]json.RawMessage{}
	if err := json.Unmarshal(logic, &root); err != nil {
		return MatchResult{}, fmt.Errorf("rule logic is not a JSON object: %w", err)
	}

	category := CategoryAuth
	exprBlob := logic

	if catRaw, ok := root["category"]; ok {
		var catStr string
		if err := json.Unmarshal(catRaw, &catStr); err != nil {
			return MatchResult{}, fmt.Errorf("rule logic.category must be a string: %w", err)
		}
		category = ParseCategory(catStr)

		var ok bool
		exprBlob, ok = root["expr"]
		if !ok {
			return MatchResult{}, errors.New("rule logic with category must include an expr field")
		}
	}

	matched, detail, err := evaluateExpression(exprBlob, signals)
	if err != nil {
		return MatchResult{}, err
	}

	return MatchResult{
		Matched:  matched,
		Category: category,
		Detail:   detail,
	}, nil
}

// ExplicitCategory reports whether the top-level rule logic blob
// declared a "category" field. Useful for callers that need to fall
// back to a default category derived from rules.target.
func ExplicitCategory(logic json.RawMessage) bool {
	root := map[string]json.RawMessage{}
	if err := json.Unmarshal(logic, &root); err != nil {
		return false
	}
	_, ok := root["category"]
	return ok
}

// ParseCategory normalises a free-form category string into one of the
// canonical Category values, defaulting to CategoryAuth on unknown
// inputs (so a rule with a typo in its category still contributes to
// some bucket deterministically rather than being silently dropped).
func ParseCategory(raw string) Category {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auth", "authentication":
		return CategoryAuth
	case "reputation", "rep":
		return CategoryReputation
	case "structural", "structure":
		return CategoryStructural
	default:
		return CategoryAuth
	}
}

func evaluateExpression(blob json.RawMessage, signals SignalSnapshot) (bool, map[string]any, error) {
	if len(blob) == 0 {
		return false, nil, errors.New("empty expression")
	}

	root := map[string]json.RawMessage{}
	if err := json.Unmarshal(blob, &root); err != nil {
		return false, nil, fmt.Errorf("expression is not a JSON object: %w", err)
	}

	switch {
	case keyPresent(root, "all"):
		return evaluateAll(root["all"], signals)
	case keyPresent(root, "any"):
		return evaluateAny(root["any"], signals)
	case keyPresent(root, "not"):
		return evaluateNot(root["not"], signals)
	case keyPresent(root, "signal") && keyPresent(root, "op"):
		return evaluateLeaf(root, signals)
	default:
		return false, nil, errors.New("expression must contain one of: all, any, not, or (signal+op)")
	}
}

func evaluateAll(blob json.RawMessage, signals SignalSnapshot) (bool, map[string]any, error) {
	var children []json.RawMessage
	if err := json.Unmarshal(blob, &children); err != nil {
		return false, nil, fmt.Errorf("all: expected array, got %s", string(blob))
	}
	details := make([]map[string]any, 0, len(children))
	for i, c := range children {
		matched, detail, err := evaluateExpression(c, signals)
		if err != nil {
			return false, nil, fmt.Errorf("all[%d]: %w", i, err)
		}
		if !matched {
			return false, nil, nil
		}
		if detail != nil {
			details = append(details, detail)
		}
	}
	return true, map[string]any{"all": details}, nil
}

func evaluateAny(blob json.RawMessage, signals SignalSnapshot) (bool, map[string]any, error) {
	var children []json.RawMessage
	if err := json.Unmarshal(blob, &children); err != nil {
		return false, nil, fmt.Errorf("any: expected array, got %s", string(blob))
	}
	for i, c := range children {
		matched, detail, err := evaluateExpression(c, signals)
		if err != nil {
			return false, nil, fmt.Errorf("any[%d]: %w", i, err)
		}
		if matched {
			return true, map[string]any{"any": detail}, nil
		}
	}
	return false, nil, nil
}

func evaluateNot(blob json.RawMessage, signals SignalSnapshot) (bool, map[string]any, error) {
	matched, _, err := evaluateExpression(blob, signals)
	if err != nil {
		return false, nil, fmt.Errorf("not: %w", err)
	}
	return !matched, map[string]any{"not": matched}, nil
}

func evaluateLeaf(root map[string]json.RawMessage, signals SignalSnapshot) (bool, map[string]any, error) {
	var signal string
	if err := json.Unmarshal(root["signal"], &signal); err != nil {
		return false, nil, fmt.Errorf("signal must be a string: %w", err)
	}

	var op string
	if err := json.Unmarshal(root["op"], &op); err != nil {
		return false, nil, fmt.Errorf("op must be a string: %w", err)
	}

	var value any
	if raw, ok := root["value"]; ok {
		if err := json.Unmarshal(raw, &value); err != nil {
			return false, nil, fmt.Errorf("value: %w", err)
		}
	}

	actual, hasActual := signals[signal]
	matched := false

	switch strings.ToLower(strings.TrimSpace(op)) {
	case "eq":
		matched = hasActual && equalValues(actual, value)
	case "neq":
		matched = hasActual && !equalValues(actual, value)
	case "gt":
		matched = hasActual && compareNumbers(actual, value) > 0
	case "gte":
		matched = hasActual && compareNumbers(actual, value) >= 0
	case "lt":
		matched = hasActual && compareNumbers(actual, value) < 0
	case "lte":
		matched = hasActual && compareNumbers(actual, value) <= 0
	case "in":
		matched = hasActual && valueInList(actual, value)
	case "not_in":
		matched = hasActual && !valueInList(actual, value)
	case "contains":
		matched = hasActual && stringContains(actual, value)
	case "exists":
		matched = hasActual
	case "missing":
		matched = !hasActual
	default:
		return false, nil, fmt.Errorf("unsupported op %q", op)
	}

	return matched, map[string]any{
		"signal": signal,
		"op":     op,
		"value":  value,
		"actual": actual,
	}, nil
}

func keyPresent(m map[string]json.RawMessage, k string) bool {
	_, ok := m[k]
	return ok
}

func equalValues(a, b any) bool {
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && strings.EqualFold(av, bv)
	}

	an, aOK := toFloat(a)
	bn, bOK := toFloat(b)
	if aOK && bOK {
		return an == bn
	}

	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func compareNumbers(a, b any) int {
	an, aOK := toFloat(a)
	bn, bOK := toFloat(b)
	if !aOK || !bOK {
		return 0
	}
	switch {
	case an < bn:
		return -1
	case an > bn:
		return 1
	default:
		return 0
	}
}

func valueInList(actual, list any) bool {
	arr, ok := list.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		if equalValues(actual, item) {
			return true
		}
	}
	return false
}

func stringContains(actual, needle any) bool {
	s, ok := actual.(string)
	if !ok {
		return false
	}
	n, ok := needle.(string)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(n))
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
