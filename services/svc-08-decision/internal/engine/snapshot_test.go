package engine

import (
	"testing"

	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestBuildSnapshot_PopulatesAllPresentSignals(t *testing.T) {
	scored := contracts.EmailsScored{
		PartialAnalysis: false,
		URLScore:        ptrInt(80),
		HeaderScore:     ptrInt(60),
		NLPScore:        ptrInt(40),
		// AttachmentScore intentionally nil
	}
	snap := BuildSnapshot(SnapshotInputs{
		Scored:       scored,
		Components:   ComponentsFrom(scored),
		BlendedScore: 65.5,
		NudgedScore:  68.0,
		PreRuleLabel: LabelPhishing,
		CampaignState: &campaign.History{
			CampaignID: 17,
			RiskScore:  85,
			EmailCount: 12,
		},
	})

	for _, k := range []string{
		"score.url", "score.header", "score.nlp",
		"score.blended", "score.campaign_nudged",
		"partial_analysis", "verdict.label",
		"campaign.is_new", "campaign.risk_score", "campaign.email_count",
	} {
		if _, ok := snap[k]; !ok {
			t.Errorf("snapshot missing required key %q", k)
		}
	}
	if _, ok := snap["score.attachment"]; ok {
		t.Errorf("snapshot has score.attachment when component was nil")
	}
	if snap["campaign.is_new"].(bool) {
		t.Errorf("campaign.is_new = true, want false (history present)")
	}
}

func TestBuildSnapshot_NewCampaignFlagsCorrectly(t *testing.T) {
	snap := BuildSnapshot(SnapshotInputs{
		Scored:        contracts.EmailsScored{},
		Components:    Components{},
		BlendedScore:  0,
		NudgedScore:   0,
		PreRuleLabel:  LabelBenign,
		CampaignState: nil,
	})
	if got := snap["campaign.is_new"].(bool); !got {
		t.Errorf("campaign.is_new = false, want true (no history)")
	}
	if got := snap["campaign.risk_score"].(float64); got != 0 {
		t.Errorf("campaign.risk_score = %v, want 0", got)
	}
}
