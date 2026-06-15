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
		// verdict.label is the PRE-RULE pure score→band label (LabelFor), NOT
		// the final reconciled verdict. Rules match on it before they run, so it
		// deliberately ignores the malware-vs-phishing(high) attachment
		// reconcile: a high-band email with no malware-grade attachment shows
		// here as "malware" even though its final verdict is "phishing". Rule
		// authors keying on verdict.label == "malware" are matching the band,
		// not the published label. See engine.go (preRuleLabel) and brief §3.5.
		"verdict.label": string(in.PreRuleLabel),
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
//
// A component flagged in DegradedComponents produced a score on a fail-soft
// fallback path (e.g. svc-06's neutral content score after a model timeout). A
// fallback is not a measurement, so it is treated as ABSENT rather than fused:
// otherwise svc-06's neutral 50 — which under the P(phishing) content scoring is
// a *moderate phishing* value, not a neutral one — would push a legit email's
// verdict up during an NLP outage. Absent means the verdict relies on the other
// channels (or stays benign), which is the correct fail-soft behaviour.
func ComponentsFrom(s contracts.EmailsScored) Components {
	c := Components{
		URL:        s.URLScore,
		Header:     s.HeaderScore,
		NLP:        s.NLPScore,
		Attachment: s.AttachmentScore,
	}
	for _, d := range s.DegradedComponents {
		switch d {
		case contracts.TopicScoresURL:
			c.URL = nil
		case contracts.TopicScoresHeader:
			c.Header = nil
		case contracts.TopicScoresNLP:
			c.NLP = nil
		case contracts.TopicScoresAttachment:
			c.Attachment = nil
		}
	}
	return c
}
