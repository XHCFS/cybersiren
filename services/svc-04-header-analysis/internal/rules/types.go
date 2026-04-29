// Package rules holds the rule cache, DSL interpreter, and evaluator for
// SVC-04 Header Analysis. The same primitives can be reused by SVC-08.
package rules

import "encoding/json"

// CachedRule is the in-memory shape of a rule loaded from Postgres.
//
// Each rule definition is immutable once loaded — the cache replaces
// the entire rule set on refresh, so callers can hold a slice of these
// safely without locking until a refresh swaps it.
type CachedRule struct {
	ID          int64           `json:"id"`
	OrgID       *int64          `json:"org_id,omitempty"` // nil = global rule
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Target      string          `json:"target"`
	ScoreImpact int             `json:"score_impact"`
	Logic       json.RawMessage `json:"logic"`
}

// FiredRule is the output of evaluating a single rule that matched.
type FiredRule struct {
	Rule        CachedRule
	MatchDetail json.RawMessage
}
