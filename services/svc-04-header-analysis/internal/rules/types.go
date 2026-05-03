// Package rules holds the rule cache, DSL interpreter, and evaluator for
// SVC-04 Header Analysis. The DSL itself now lives in
// shared/rules/dsl so it can be reused by SVC-08 and future analysers;
// this package keeps the SVC-04-specific concerns (signal snapshot
// from header signals, category-aware Evaluator, three-tier cache).
package rules

import (
	"github.com/saif/cybersiren/shared/rules/dsl"
)

// CachedRule is the in-memory shape of a rule loaded from Postgres.
// Aliased to the shared DSL type so SVC-08 and SVC-04 read the same
// rule shape without conversion.
type CachedRule = dsl.CachedRule

// FiredRule is the output of evaluating a single rule that matched.
type FiredRule = dsl.FiredRule
