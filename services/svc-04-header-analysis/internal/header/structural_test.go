package header

import (
	"encoding/json"
	"math"
	"testing"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestExtractStructural_HopCountAndDrift(t *testing.T) {
	t.Parallel()

	// Sent at epoch 1700000000s; the latest Received hop is +25h later.
	const sent = int64(1700000000)
	const received = sent + 25*3600

	msg := &contractsk.AnalysisHeadersMessage{
		HopCount:      20,
		MailerAgent:   "Outlook 16",
		SentTimestamp: sent,
		ReceivedChain: []contractsk.ReceivedHop{
			{From: "a", By: "b", Timestamp: sent + 3600},
			{From: "c", By: "d", Timestamp: received},
		},
	}

	got := ExtractStructural(msg, StructuralExtractorConfig{
		HopCountThreshold:       15,
		TimeDriftHoursThreshold: 24,
	})

	if got.HopCount != 20 || !got.HopCountAboveThreshold {
		t.Errorf("hop count flag wrong: %+v", got)
	}
	if math.Abs(got.TimeDriftHours-25) > 0.001 {
		t.Errorf("time drift = %v, want ≈25h", got.TimeDriftHours)
	}
	if !got.TimeDriftAboveThreshold {
		t.Errorf("expected drift above threshold")
	}
	if got.MissingMailer || got.SuspiciousMailerAgent {
		t.Errorf("Outlook should not be suspicious: %+v", got)
	}
}

func TestExtractStructural_MissingMailer(t *testing.T) {
	t.Parallel()

	got := ExtractStructural(&contractsk.AnalysisHeadersMessage{
		HopCount: 1,
	}, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	if !got.MissingMailer {
		t.Errorf("MissingMailer should be true when MailerAgent absent")
	}
	if got.SuspiciousMailerAgent {
		t.Errorf("SuspiciousMailerAgent should be false when MissingMailer")
	}
}

func TestExtractStructural_SuspiciousMailer(t *testing.T) {
	t.Parallel()

	got := ExtractStructural(&contractsk.AnalysisHeadersMessage{
		MailerAgent: "PHPMailer 5.2",
	}, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	if !got.SuspiciousMailerAgent {
		t.Errorf("PHPMailer should be flagged suspicious")
	}
}

func TestExtractStructural_VendorTagsFromHeadersJSON(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"From":                 "alice@example.com",
		"x-microsoft-antispam": "BCL:0",
		"X-Spam-Status":        "Yes, score=12.4",
	}
	raw, _ := json.Marshal(headers)

	got := ExtractStructural(&contractsk.AnalysisHeadersMessage{
		HeadersJSON: raw,
	}, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	if !got.HasVendorSecurityTag {
		t.Errorf("HasVendorSecurityTag should be true given known headers, got %+v", got)
	}
}

func TestExtractStructural_NilMessage(t *testing.T) {
	t.Parallel()

	got := ExtractStructural(nil, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	// StructuralSignals contains a slice and is therefore not directly
	// comparable; check the fields that matter.
	if got.HopCount != 0 || got.HopCountAboveThreshold || got.TimeDriftHours != 0 ||
		got.TimeDriftAboveThreshold || got.HasVendorSecurityTag || len(got.VendorTagNames) != 0 ||
		got.MailerAgent != "" || got.MissingMailer || got.SuspiciousMailerAgent {
		t.Errorf("ExtractStructural(nil) should return zero value, got %+v", got)
	}
}

func TestExtractStructural_MalformedHeadersJSONIsTolerated(t *testing.T) {
	t.Parallel()

	got := ExtractStructural(&contractsk.AnalysisHeadersMessage{
		HeadersJSON: json.RawMessage([]byte("{not-json")),
	}, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	// Malformed JSON must not panic — it just yields no vendor tags.
	if got.HasVendorSecurityTag {
		t.Errorf("expected HasVendorSecurityTag=false, got true: %+v", got)
	}
}
