package notifier

import (
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Alert is the channel-agnostic payload built from an emails.verdict once it
// has crossed the gate. Each channel renders it into its own wire shape (an
// email body, a JSON webhook body).
type Alert struct {
	OrgID        int64     `json:"org_id"`
	EmailID      int64     `json:"email_id"`
	InternalID   int64     `json:"internal_id"`
	VerdictLabel string    `json:"verdict_label"`
	RiskScore    int       `json:"risk_score"`
	Confidence   float64   `json:"confidence"`
	CampaignID   *int64    `json:"campaign_id,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`

	// Recipients is the admin email list (email channel only).
	Recipients []string `json:"recipients,omitempty"`
}

// AlertFrom builds an Alert from a verdict and the resolved org prefs.
func AlertFrom(v contracts.EmailsVerdict, prefs OrgPrefs) Alert {
	return Alert{
		OrgID:        v.Meta.OrgID,
		EmailID:      v.Meta.EmailID,
		InternalID:   v.InternalID,
		VerdictLabel: v.VerdictLabel,
		RiskScore:    v.RiskScore,
		Confidence:   v.Confidence,
		CampaignID:   v.CampaignID,
		IssuedAt:     time.Now().UTC(),
		Recipients:   prefs.AdminEmails,
	}
}
