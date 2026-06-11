package main

import (
	"encoding/json"
	"net/mail"
	"testing"

	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// newHeaderView must merge EVERY Authentication-Results header before parsing,
// not just the first/topmost. Real mail carries one AR header per authenticating
// hop; a DMARC result living in a non-first header was being reported as missing
// to svc-04 (the old code used Header.Get = first occurrence only).
func TestNewHeaderViewMergesAllAuthResults(t *testing.T) {
	parsed := &email.ParsedEmail{
		Header: mail.Header{
			"From": []string{"a@b.example"},
			"Authentication-Results": []string{
				"mx1.corp.example; spf=pass smtp.mailfrom=acme.example",
				"mx2.corp.example; dmarc=fail",
			},
		},
	}

	hv := newHeaderView(parsed)
	if hv.auth["spf"] != "pass" {
		t.Errorf("auth[spf] = %q, want pass (from first AR header)", hv.auth["spf"])
	}
	if hv.auth["dmarc"] != "fail" {
		t.Errorf("auth[dmarc] = %q, want fail (from second AR header — must be merged, not dropped)", hv.auth["dmarc"])
	}
}

// A subject-only (body-less) email must still declare the NLP topic in the plan
// so svc-07 keeps the NLP score svc-06 produces for the subject; HasBody alone
// would omit it and silently drop the signal from the fusion verdict.
func TestBuildAnalysisPlanSubjectOnlyDeclaresNLP(t *testing.T) {
	parsed := &email.ParsedEmail{Subject: "Your account is locked, call this number"}
	plan := buildAnalysisPlan(contracts.MessageMeta{}, parsed)

	hasNLP := false
	for _, s := range plan.ExpectedScores {
		if s == contracts.TopicScoresNLP {
			hasNLP = true
		}
	}
	if !hasNLP {
		t.Errorf("ExpectedScores = %v, want it to include the NLP topic for a subject-only email", plan.ExpectedScores)
	}
	if plan.HasBody {
		t.Error("plan.HasBody = true for a body-less email, want false")
	}
}

// A two-hop Received chain: index 0 is the receiving MX (most recent), the last
// entry is the originating sender. Proves received_chain is populated and that
// originatingAddr picks the ORIGIN hop's IP, not the topmost MX (SF-1: the old
// code used Header.Get("Received") = the first/topmost = wrong hop).
func TestReceivedChainAndOriginatingAddr(t *testing.T) {
	h := mail.Header{
		"Received": []string{
			"from relay.receiver.com (relay.receiver.com [198.51.100.7]) by mx.receiver.com (Postfix) with ESMTPS id ABC; Mon, 09 Jun 2026 15:31:09 +0000",
			"from mail.sender.com (mail.sender.com [203.0.113.5]) by relay.receiver.com (Postfix) with ESMTP id DEF; Mon, 09 Jun 2026 15:31:07 +0000",
		},
	}

	chain := receivedChain(h)
	if len(chain) != 2 {
		t.Fatalf("received_chain len = %d, want 2", len(chain))
	}
	if chain[0].From != "relay.receiver.com" || chain[0].By != "mx.receiver.com" {
		t.Errorf("hop[0] = %+v, want from=relay.receiver.com by=mx.receiver.com", chain[0])
	}
	if chain[1].From != "mail.sender.com" {
		t.Errorf("hop[1].From = %q, want mail.sender.com", chain[1].From)
	}
	if chain[0].Timestamp == 0 || chain[1].Timestamp == 0 {
		t.Errorf("hop timestamps not parsed: %+v", chain)
	}

	got := originatingAddr(h)
	if got == nil || got.String() != "203.0.113.5" {
		t.Fatalf("originatingAddr = %v, want 203.0.113.5 (the origin hop, not the topmost relay)", got)
	}
}

// When the origin hop carries a private/internal IP, originatingAddr skips it
// and returns the first PUBLIC address scanning toward the most-recent hop.
func TestOriginatingAddrSkipsPrivateOrigin(t *testing.T) {
	h := mail.Header{
		"Received": []string{
			"from edge.receiver.com (edge.receiver.com [198.51.100.7]) by mx.receiver.com; Mon, 09 Jun 2026 15:31:09 +0000",
			"from internal.lan (internal.lan [10.0.0.5]) by edge.receiver.com; Mon, 09 Jun 2026 15:31:07 +0000",
		},
	}
	got := originatingAddr(h)
	if got == nil || got.String() != "198.51.100.7" {
		t.Fatalf("originatingAddr = %v, want 198.51.100.7 (skip the private origin)", got)
	}
}

// No Received headers → nil chain and nil originating addr (no panic).
func TestReceivedChainEmpty(t *testing.T) {
	h := mail.Header{}
	if chain := receivedChain(h); chain != nil {
		t.Errorf("received_chain = %v, want nil", chain)
	}
	if got := originatingAddr(h); got != nil {
		t.Errorf("originatingAddr = %v, want nil", got)
	}
}

// headers_json must keep every value of a repeated header. The old code stored
// only vv[0], silently dropping all but the first Received line; the map is now
// map[string][]string so the full chain survives the round-trip.
func TestHeaderMapJSONPreservesRepeatedHeaders(t *testing.T) {
	h := mail.Header{
		"Received": []string{
			"from relay.receiver.com by mx.receiver.com",
			"from mail.sender.com by relay.receiver.com",
			"from origin.example by mail.sender.com",
		},
		"Authentication-Results": []string{
			"mx.receiver.com; spf=pass",
			"relay.receiver.com; dkim=pass",
		},
		"Subject": []string{"hello"},
	}

	raw := headerMapJSON(h)
	var got map[string][]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("headers_json is not a map[string][]string: %v (raw=%s)", err, raw)
	}

	if len(got["Received"]) != 3 {
		t.Fatalf("headers_json Received len = %d, want 3 (repeated values must be preserved): %v", len(got["Received"]), got["Received"])
	}
	for i, want := range h["Received"] {
		if got["Received"][i] != want {
			t.Errorf("headers_json Received[%d] = %q, want %q", i, got["Received"][i], want)
		}
	}

	if len(got["Authentication-Results"]) != 2 {
		t.Errorf("headers_json Authentication-Results len = %d, want 2: %v", len(got["Authentication-Results"]), got["Authentication-Results"])
	}

	if len(got["Subject"]) != 1 || got["Subject"][0] != "hello" {
		t.Errorf("headers_json Subject = %v, want [hello]", got["Subject"])
	}
}

// attachmentObjectKey is content-addressed and org-agnostic: identical bytes
// must map to one global key regardless of tenant, with the sha256 two-level
// fan-out preserved (attachment_library is a global content-addressed table).
func TestAttachmentObjectKeyIsOrgAgnostic(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := attachmentObjectKey(sha)
	want := "attachments/01/23/" + sha
	if got != want {
		t.Fatalf("attachmentObjectKey = %q, want %q", got, want)
	}
}

// A missing/short hash still yields a stable two-level key (defensive path).
func TestAttachmentObjectKeyShortHash(t *testing.T) {
	got := attachmentObjectKey("ab")
	if got == "attachments/ab" || len(got) <= len("attachments///") {
		t.Fatalf("attachmentObjectKey(short) = %q, want a stable fanned key", got)
	}
	// Same short input must be deterministic.
	if again := attachmentObjectKey("ab"); again != got {
		t.Fatalf("attachmentObjectKey(short) not deterministic: %q vs %q", got, again)
	}
}
