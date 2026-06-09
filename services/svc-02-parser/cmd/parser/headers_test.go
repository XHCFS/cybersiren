package main

import (
	"net/mail"
	"testing"
)

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
