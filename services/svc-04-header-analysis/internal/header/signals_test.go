package header

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAsContract_CarriesSenderDomain guards the cross-service contract that
// SVC-08's campaign fingerprint depends on: scores.header.signals must carry
// sender_domain (ARCH-SPEC §8.1). The wire key is asserted explicitly because
// SVC-08 reads it via the literal JSON path signals.sender_domain.
func TestAsContract_CarriesSenderDomain(t *testing.T) {
	in := HeaderSignals{
		Reputation: ReputationSignals{SenderDomain: "evil.example.com"},
	}

	out := in.AsContract()
	if out.SenderDomain != "evil.example.com" {
		t.Fatalf("AsContract().SenderDomain = %q, want evil.example.com", out.SenderDomain)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal HeaderSignals: %v", err)
	}
	var probe struct {
		SenderDomain string `json:"sender_domain"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal HeaderSignals: %v", err)
	}
	if probe.SenderDomain != "evil.example.com" {
		t.Fatalf("signals.sender_domain on wire = %q, want evil.example.com (SVC-08 reads this key)", probe.SenderDomain)
	}
}

// TestAsContract_EmptySenderDomainOmitted confirms the omitempty tag keeps the
// wire clean when SVC-04 could not derive a sender domain.
func TestAsContract_EmptySenderDomainOmitted(t *testing.T) {
	raw, err := json.Marshal(HeaderSignals{}.AsContract())
	if err != nil {
		t.Fatalf("marshal HeaderSignals: %v", err)
	}
	if got := string(raw); strings.Contains(got, "sender_domain") {
		t.Fatalf("empty sender_domain should be omitted, got %s", got)
	}
}
