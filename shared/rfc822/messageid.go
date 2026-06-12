// Package rfc822 holds small helpers for canonicalising RFC 822 / RFC 5322
// message metadata that must stay in lockstep across services.
package rfc822

import (
	"net/mail"
	"strings"
)

// MessageID extracts the RFC 5322 Message-ID from a raw RFC-822 message,
// stripping the angle brackets so the dedup key matches svc-02's
// email_identities registration (which trims "<>"). Returns "" when the header
// is absent or the message is unparseable — such messages are simply not
// deduplicated.
//
// This is the single source of truth for svc-01's dedup message_id derivation
// (the API-upload and Gmail adapters both call it); its trimming MUST match
// svc-02's email_identities registration, or dedup keys diverge from the
// registry.
func MessageID(raw []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return ""
	}
	return TrimMessageID(msg.Header.Get("Message-Id"))
}

// TrimMessageID strips the surrounding angle brackets from an RFC 5322
// Message-ID so the value is canonical wherever it is used as a key — svc-01's
// dedup claim and svc-02's email_identities registration. It is the single
// source of truth for that trimming: a caller that already holds a Message-ID
// string (a JSON request field, a parsed header) must run it through here so
// its key matches one derived from raw bytes via MessageID. Returns "" for an
// empty input.
func TrimMessageID(s string) string {
	return strings.Trim(s, "<>")
}
