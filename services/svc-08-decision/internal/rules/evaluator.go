package rules

import (
	"encoding/json"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/rules/dsl"
)

// Evaluator runs each rule's JSON-DSL logic against a SignalSnapshot
// and accumulates fired rules + total score impact. Unlike svc-04's
// Evaluator (which computes auth/reputation/structural sub-scores),
// SVC-08 just needs the flat list of fires and the summed impact for
// the final-score adjustment.
type Evaluator struct {
	log zerolog.Logger
}

// NewEvaluator constructs a stateless Evaluator. Pass logger.Disabled
// for tests to avoid noise from intentionally malformed-rule fixtures.
func NewEvaluator(log zerolog.Logger) *Evaluator {
	return &Evaluator{log: log}
}

// Evaluate iterates ruleset against snapshot and returns:
//   - fired:       in source order, the rules that matched (with their
//     match detail attached for rule_hits persistence).
//   - totalImpact: Σ rule.score_impact over fires (NOT clamped — the
//     engine clamps the final blended+nudge+impact total).
//
// Malformed rule blobs are logged and skipped (ARCH-SPEC §6).
func (e *Evaluator) Evaluate(ruleset []CachedRule, snapshot SignalSnapshot) (fired []FiredRule, totalImpact int) {
	for _, r := range ruleset {
		match, err := dsl.Evaluate(r.Logic, snapshot)
		if err != nil {
			e.log.Warn().
				Err(err).
				Int64("rule_id", r.ID).
				Str("rule_name", r.Name).
				Str("rule_version", r.Version).
				Msg("decision: malformed rule logic; skipping (score impact = 0)")
			continue
		}
		if !match.Matched {
			continue
		}
		detail, _ := json.Marshal(map[string]any{
			"rule_name": r.Name,
			"signal":    match.Detail,
		})
		fired = append(fired, FiredRule{Rule: r, MatchDetail: detail})
		totalImpact += r.ScoreImpact
	}
	return fired, totalImpact
}
