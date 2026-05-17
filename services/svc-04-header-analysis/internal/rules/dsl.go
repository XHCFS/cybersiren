package rules

import (
	"github.com/saif/cybersiren/shared/rules/dsl"
)

// SVC-04's DSL has been extracted to shared/rules/dsl so SVC-08 (and
// any future analyser) can reuse the interpreter without crossing the
// internal/ import boundary. We re-export the names SVC-04's existing
// callers depend on as type aliases so this refactor is source-
// compatible — nothing inside SVC-04 needs to change.

// Category is the sub-score bucket a rule contributes to.
type Category = dsl.Category

const (
	CategoryAuth       = dsl.CategoryAuth
	CategoryReputation = dsl.CategoryReputation
	CategoryStructural = dsl.CategoryStructural
)

// SignalSnapshot is the flat, pure value bag the DSL evaluates against.
type SignalSnapshot = dsl.SignalSnapshot

// MatchResult represents the output of a single rule evaluation.
type MatchResult = dsl.MatchResult

// Evaluate is re-exported here so callers can keep importing
// `rules.Evaluate` rather than reaching into shared/rules/dsl.
var Evaluate = dsl.Evaluate
