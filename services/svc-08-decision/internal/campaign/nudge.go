package campaign

import "math"

// History captures the campaign-level signals fed into the
// empirical-Bayes shrinkage. EmailCount = 0 represents a brand-new
// campaign (no prior emails); the nudge function then leaves the
// score untouched.
type History struct {
	CampaignID int64
	RiskScore  int // [0..100]
	EmailCount int
}

// Shrinkage configures the campaign-informed score nudge described in
// design brief §3.9 and the shrinkage research in §A-Q3.
//
// The nudge is a soft Empirical-Bayes shrinkage of the email's blended
// score toward the campaign's running mean. A capped α prevents
// campaign reputation from single-handedly flipping the verdict label
// — the campaign serves as a soft prior, never an override.
type Shrinkage struct {
	// Tau is the pseudo-count parameter. Larger values shrink LESS
	// aggressively (campaign history needs more emails before it
	// influences this email). v1 default = 5.
	Tau float64
	// AlphaMax caps the shrinkage weight so even a very-long-running
	// campaign cannot pull a score by more than this fraction of the
	// campaign-vs-email gap. v1 default = 0.30.
	AlphaMax float64
}

// DefaultShrinkage returns the v1 starting parameters.
func DefaultShrinkage() Shrinkage {
	return Shrinkage{Tau: 5.0, AlphaMax: 0.30}
}

// Nudge applies the shrinkage formula:
//
//	α        = min( n / (n + τ), α_max )
//	nudged   = (1 - α) · score_email + α · campaign_mean
//
// where n is the number of prior emails in the campaign. Returns the
// nudged score (clamped to [0, 100]) and the α actually applied (for
// logging / metrics / explainability).
//
// When campaign is nil (new campaign) or n == 0, α is 0 and the email
// score passes through unchanged. When the campaign has no risk_score
// (legacy data), the nudge is also skipped.
func Nudge(emailScore float64, campaign *History, cfg Shrinkage) (float64, float64) {
	if campaign == nil || campaign.EmailCount <= 0 {
		return clampFloat(emailScore, 0, 100), 0
	}
	if cfg.Tau <= 0 {
		cfg.Tau = 5.0
	}
	if cfg.AlphaMax <= 0 {
		cfg.AlphaMax = 0.30
	}

	n := float64(campaign.EmailCount)
	alpha := n / (n + cfg.Tau)
	if alpha > cfg.AlphaMax {
		alpha = cfg.AlphaMax
	}
	nudged := (1-alpha)*emailScore + alpha*float64(campaign.RiskScore)
	return clampFloat(nudged, 0, 100), alpha
}

func clampFloat(v, lo, hi float64) float64 {
	if math.IsNaN(v) {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
