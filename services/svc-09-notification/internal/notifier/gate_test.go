package notifier

import (
	"testing"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func verdict(score int, label string) contracts.EmailsVerdict {
	return contracts.EmailsVerdict{RiskScore: score, VerdictLabel: label}
}

func TestGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		score     int
		label     string
		threshold int
		want      bool
	}{
		{"score above threshold", 80, "suspicious", 70, true},
		{"score equals threshold", 70, "suspicious", 70, true},
		{"score below threshold benign", 40, "benign", 70, false},
		{"phishing below threshold still alerts", 30, "phishing", 70, true},
		{"malware below threshold still alerts", 10, "malware", 70, true},
		{"phishing uppercase still alerts", 30, "PHISHING", 70, true},
		{"phishing padded still alerts", 30, "  phishing  ", 70, true},
		{"spam below threshold no alert", 50, "spam", 70, false},
		{"suspicious below threshold no alert", 69, "suspicious", 70, false},
		{"unknown label below threshold no alert", 50, "unknown", 70, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Gate(verdict(tc.score, tc.label), tc.threshold); got != tc.want {
				t.Fatalf("Gate(score=%d label=%q thr=%d) = %v, want %v",
					tc.score, tc.label, tc.threshold, got, tc.want)
			}
		})
	}
}
