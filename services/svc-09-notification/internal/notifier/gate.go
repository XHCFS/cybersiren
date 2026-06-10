package notifier

import (
	"strings"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// DefaultThreshold is the fallback alert threshold used when an org row carries
// a NULL notification_threshold. It matches the migration-030 column default
// (and the pre-migration config default documented in ARCH-SPEC §1-step6a).
const DefaultThreshold = 70

// alwaysAlertLabels is the set of verdict labels that trigger an alert
// regardless of the numeric threshold (ARCH-SPEC §1 SVC-09: "If risk_score >=
// threshold OR verdict_label in {phishing, malware}"). Labels are compared
// case-insensitively.
var alwaysAlertLabels = map[string]struct{}{
	"phishing": {},
	"malware":  {},
}

// Gate is the pure threshold/label decision. threshold is the org's configured
// notification_threshold (callers pass DefaultThreshold when the column is
// NULL). It returns true when the verdict should raise an alert.
//
// A verdict alerts when its blended risk score is at or above the org
// threshold, OR when its label is one of the always-alert labels (phishing,
// malware) even if the score happens to sit below the threshold. This mirrors
// the OR semantics in the spec and keeps a high-confidence phishing/malware
// label from being silently dropped by a high org threshold.
func Gate(v contracts.EmailsVerdict, threshold int) bool {
	if v.RiskScore >= threshold {
		return true
	}
	_, always := alwaysAlertLabels[strings.ToLower(strings.TrimSpace(v.VerdictLabel))]
	return always
}
