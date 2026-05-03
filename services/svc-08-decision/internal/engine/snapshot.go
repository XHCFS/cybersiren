package engine

import (
	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// SnapshotInputs gathers everything the rules DSL might want to inspect
// when SVC-08 is evaluating a single email.
type SnapshotInputs struct {
	Scored        contracts.EmailsScored
	Components    Components
	BlendedScore  float64
	NudgedScore   float64
	PreRuleLabel  Label
	CampaignState *campaign.History
}

// BuildSnapshot flattens SnapshotInputs into the SignalSnapshot shape
// the JSON-DSL evaluator consumes. Keys match the documented signal
// surface in docs/design/svc-07-08-design-brief.md §3.5.
func BuildSnapshot(in SnapshotInputs) rules.SignalSnapshot {
	snap := rules.SignalSnapshot{
		"score.blended":         in.BlendedScore,
		"score.campaign_nudged": in.NudgedScore,
		"partial_analysis":      in.Scored.PartialAnalysis,
		"verdict.label":         string(in.PreRuleLabel),
	}

	if in.Components.URL != nil {
		snap["score.url"] = float64(*in.Components.URL)
	}
	if in.Components.Header != nil {
		snap["score.header"] = float64(*in.Components.Header)
	}
	if in.Components.NLP != nil {
		snap["score.nlp"] = float64(*in.Components.NLP)
	}
	if in.Components.Attachment != nil {
		snap["score.attachment"] = float64(*in.Components.Attachment)
	}

	if in.CampaignState != nil {
		snap["campaign.is_new"] = false
		snap["campaign.risk_score"] = float64(in.CampaignState.RiskScore)
		snap["campaign.email_count"] = in.CampaignState.EmailCount
	} else {
		snap["campaign.is_new"] = true
		snap["campaign.risk_score"] = 0.0
		snap["campaign.email_count"] = 0
	}
	return snap
}

// ComponentsFrom extracts the typed Components view from an EmailsScored
// message — the engine operates on the typed view rather than the raw
// JSON throughout.
func ComponentsFrom(s contracts.EmailsScored) Components {
	return Components{
		URL:        s.URLScore,
		Header:     s.HeaderScore,
		NLP:        s.NLPScore,
		Attachment: s.AttachmentScore,
	}
}
