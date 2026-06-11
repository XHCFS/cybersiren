package header

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// TestDataFlow_OriginatingIPAndReceivedChainReachSignals locks in the P2.3
// data-flow fix: now that the parser populates originating_ip and
// received_chain on analysis.headers, the IP-TI reputation signal and the
// timestamp-drift structural signal must actually fire end-to-end.
func TestDataFlow_OriginatingIPAndReceivedChainReachSignals(t *testing.T) {
	t.Parallel()

	const sent = int64(1700000000)
	const lastHop = sent + 30*3600 // 30h drift

	msg := &contractsk.AnalysisHeadersMessage{
		SenderDomain:  "evil-corp.example",
		OriginatingIP: "198.51.100.9",
		SentTimestamp: sent,
		ReceivedChain: []contractsk.ReceivedHop{
			{From: "mx1", By: "relay", Timestamp: sent + 3600},
			{From: "relay", By: "dest", Timestamp: lastHop},
		},
		BodyHTML: `<html><body><form action="http://evil/login"><input name="pw"></form></body></html>`,
	}

	// IP-TI must fire off originating_ip.
	stub := &stubTILookup{ipHit: true, ipScore: 88, ipType: "phishing"}
	rep := NewReputationExtractor(stub, 2, zerolog.Nop()).Extract(context.Background(), msg)
	if !rep.TIIPMatch || rep.TIIPRiskScore != 88 {
		t.Errorf("IP-TI must fire from originating_ip; got %+v", rep)
	}

	// Timestamp drift must fire from received_chain vs sent_timestamp.
	struc := ExtractStructural(msg, StructuralExtractorConfig{HopCountThreshold: 15, TimeDriftHoursThreshold: 24})
	if !struc.TimeDriftAboveThreshold {
		t.Errorf("time-drift must fire from received_chain; got drift=%.1fh above=%v", struc.TimeDriftHours, struc.TimeDriftAboveThreshold)
	}

	// Body structural (D9) must fire from the parser-shipped HTML body.
	if !struc.HasForm {
		t.Errorf("has_form must fire from the body the parser ships; got %+v", struc)
	}
}
