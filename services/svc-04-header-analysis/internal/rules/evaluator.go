package rules

import (
	"encoding/json"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-04-header-analysis/internal/header"
)

// SignalsToSnapshot flattens a HeaderSignals struct into the SignalSnapshot
// map the DSL operates on. The keys here are part of the rule contract —
// renaming one is a breaking change for the seeded rule set.
func SignalsToSnapshot(s header.HeaderSignals) SignalSnapshot {
	snap := SignalSnapshot{
		// Auth
		"auth.spf":                    string(s.Auth.SPF),
		"auth.dkim":                   string(s.Auth.DKIM),
		"auth.dmarc":                  string(s.Auth.DMARC),
		"auth.arc":                    string(s.Auth.ARC),
		"auth.from_reply_to_match":    s.Auth.FromReplyToMatch,
		"auth.from_return_path_match": s.Auth.FromReturnPathMatch,
		"auth.has_reply_to":           s.Auth.HasReplyTo,
		"auth.has_return_path":        s.Auth.HasReturnPath,

		// Reputation
		"reputation.sender_domain":         s.Reputation.SenderDomain,
		"reputation.originating_ip":        s.Reputation.OriginatingIP,
		"reputation.x_originating_ip":      s.Reputation.XOriginatingIP,
		"reputation.ti_domain_match":       s.Reputation.TIDomainMatch,
		"reputation.ti_domain_risk_score":  s.Reputation.TIDomainRiskScore,
		"reputation.ti_domain_threat_type": s.Reputation.TIDomainThreatType,
		"reputation.ti_ip_match":           s.Reputation.TIIPMatch,
		"reputation.ti_ip_risk_score":      s.Reputation.TIIPRiskScore,
		"reputation.ti_ip_threat_type":     s.Reputation.TIIPThreatType,
		"reputation.is_free_provider":      s.Reputation.IsFreeProvider,
		"reputation.typosquat_distance":    s.Reputation.TyposquatDistance,
		"reputation.typosquat_target":      s.Reputation.TyposquatTarget,

		// Structural
		"structural.hop_count":                  s.Structural.HopCount,
		"structural.hop_count_above_threshold":  s.Structural.HopCountAboveThreshold,
		"structural.time_drift_hours":           s.Structural.TimeDriftHours,
		"structural.time_drift_above_threshold": s.Structural.TimeDriftAboveThreshold,
		"structural.has_vendor_security_tag":    s.Structural.HasVendorSecurityTag,
		"structural.missing_mailer":             s.Structural.MissingMailer,
		"structural.suspicious_mailer_agent":    s.Structural.SuspiciousMailerAgent,
		"structural.mailer_agent":               s.Structural.MailerAgent,
	}
	if s.Reputation.DomainAgeDays != nil {
		snap["reputation.domain_age_days"] = *s.Reputation.DomainAgeDays
	}
	return snap
}

// EvaluationResult is the aggregated output of running a HeaderSignals
// snapshot against an entire rule set.
type EvaluationResult struct {
	Fired []FiredRule

	// Sub-score per category, clamped to [0, 100].
	AuthSubScore       int
	ReputationSubScore int
	StructuralSubScore int
}

// Evaluator iterates a slice of rules against a snapshot and returns
// the FiredRule list plus per-category sub-scores. Malformed rules are
// logged and skipped (ARCH-SPEC §6).
type Evaluator struct {
	log zerolog.Logger
}

// NewEvaluator builds a stateless evaluator. log is used for malformed-rule
// warnings; pass logger.Disabled for tests if you don't want noise.
func NewEvaluator(log zerolog.Logger) *Evaluator {
	return &Evaluator{log: log}
}

// Evaluate runs every rule in `ruleset` against `snapshot`. The order of
// rules in the input is preserved in the Fired slice so logs and the
// scores.header.fired_rules array remain deterministic.
func (e *Evaluator) Evaluate(ruleset []CachedRule, snapshot SignalSnapshot) EvaluationResult {
	result := EvaluationResult{}

	auth, rep, struc := 0, 0, 0
	for _, r := range ruleset {
		match, err := Evaluate(r.Logic, snapshot)
		if err != nil {
			e.log.Warn().
				Err(err).
				Int64("rule_id", r.ID).
				Str("rule_name", r.Name).
				Str("rule_version", r.Version).
				Msg("malformed rule logic; skipping (score impact = 0)")
			continue
		}
		if !match.Matched {
			continue
		}

		// Fall back to the rule's `target` field when category was not
		// explicitly declared in logic. The mapping is intentional:
		// `target = 'header'` → structural by default; `target = 'email'`
		// → auth by default. Rules can override this via the explicit
		// "category" field above.
		category := match.Category
		if !explicitCategory(r.Logic) {
			category = categoryFromTarget(r.Target, category)
		}

		detailRaw, _ := json.Marshal(map[string]any{
			"rule_name": r.Name,
			"category":  category,
			"signal":    match.Detail,
		})
		result.Fired = append(result.Fired, FiredRule{
			Rule:        r,
			MatchDetail: detailRaw,
		})

		switch category {
		case CategoryAuth:
			auth += r.ScoreImpact
		case CategoryReputation:
			rep += r.ScoreImpact
		case CategoryStructural:
			struc += r.ScoreImpact
		default:
			auth += r.ScoreImpact
		}
	}

	result.AuthSubScore = clamp(auth, 0, 100)
	result.ReputationSubScore = clamp(rep, 0, 100)
	result.StructuralSubScore = clamp(struc, 0, 100)
	return result
}

// FinalScore blends sub-scores into the [0,100] composite header score.
//
// The selected blend is preliminary — see HeaderConfig.ScoringBlend.
//
//	"max"      → max(auth, reputation, structural)
//	"average"  → mean of the three
//	"weighted" → weighted mean; weights normalised inside the function
func FinalScore(auth, rep, struc int, blend string, weights ...float64) int {
	switch blend {
	case "average":
		return clamp((auth+rep+struc)/3, 0, 100)
	case "weighted":
		var w1, w2, w3 float64 = 1, 1, 1
		if len(weights) >= 3 {
			w1, w2, w3 = weights[0], weights[1], weights[2]
		}
		sum := w1 + w2 + w3
		if sum <= 0 {
			sum = 3
			w1, w2, w3 = 1, 1, 1
		}
		v := (float64(auth)*w1 + float64(rep)*w2 + float64(struc)*w3) / sum
		return clamp(int(v+0.5), 0, 100)
	default: // "max" / unknown
		m := auth
		if rep > m {
			m = rep
		}
		if struc > m {
			m = struc
		}
		return clamp(m, 0, 100)
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func categoryFromTarget(target string, fallback Category) Category {
	switch target {
	case "header":
		return CategoryStructural
	case "email":
		return CategoryAuth
	default:
		return fallback
	}
}

// explicitCategory reports whether the rule logic blob explicitly
// declared a category. We avoid re-parsing the same JSON twice by
// checking byte-wise; close enough for the seed-rule contract.
func explicitCategory(logic json.RawMessage) bool {
	root := map[string]json.RawMessage{}
	if err := json.Unmarshal(logic, &root); err != nil {
		return false
	}
	_, ok := root["category"]
	return ok
}
