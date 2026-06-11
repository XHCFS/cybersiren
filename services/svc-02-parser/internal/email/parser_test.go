package email

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// buildMIME assembles a multipart/mixed message with an alternative (plain +
// html) body and one base64 attachment, plus the headers the parser projects.
func buildMIME() []byte {
	att := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 fake pdf bytes"))
	var b strings.Builder
	b.WriteString("From: \"Acme Billing\" <billing@acme.example>\r\n")
	b.WriteString("To: victim@corp.example, second@corp.example\r\n")
	b.WriteString("Cc: boss@corp.example\r\n")
	b.WriteString("Reply-To: noreply@phish.example\r\n")
	b.WriteString("Return-Path: <bounce@phish.example>\r\n")
	b.WriteString("Subject: =?utf-8?B?SW52b2ljZSBkdWU=?=\r\n") // "Invoice due"
	b.WriteString("Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n")
	b.WriteString("Message-Id: <abc123@acme.example>\r\n")
	b.WriteString("In-Reply-To: <prev@acme.example>\r\n")
	b.WriteString("References: <r1@acme.example> <r2@acme.example>\r\n")
	b.WriteString("X-Mailer: PhishKit 2.0\r\n")
	b.WriteString("Received: from mail.acme.example (1.2.3.4) by mx.corp.example\r\n")
	b.WriteString("Received: from internal by mail.acme.example\r\n")
	b.WriteString("Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=acme.example; dkim=fail; dmarc=fail\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"MIX\"\r\n")
	b.WriteString("\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"ALT\"\r\n\r\n")
	b.WriteString("--ALT\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString("Please review http://plain.example.com/invoice now.\r\n")
	b.WriteString("--ALT\r\n")
	b.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(`<html><body><p>Hi, <a href="https://html.example.com/pay">pay now</a></p></body></html>` + "\r\n")
	b.WriteString("--ALT--\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: application/pdf; name=\"invoice.pdf\"\r\n")
	b.WriteString("Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-ID: <att-1>\r\n\r\n")
	b.WriteString(att + "\r\n")
	b.WriteString("--MIX--\r\n")
	return []byte(b.String())
}

func TestParseFullMessage(t *testing.T) {
	pe, err := Parse(buildMIME())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if pe.Subject != "Invoice due" {
		t.Errorf("subject = %q, want decoded %q", pe.Subject, "Invoice due")
	}

	// Body: both plain and html captured; plain text is clean and html stripped.
	if !strings.Contains(pe.BodyPlain, "Please review") {
		t.Errorf("body_plain missing plain part: %q", pe.BodyPlain)
	}
	if !strings.Contains(pe.BodyHTML, "<a href=") {
		t.Errorf("body_html missing raw markup: %q", pe.BodyHTML)
	}
	if !pe.HasBody() {
		t.Error("HasBody() = false, want true")
	}

	// URLs: plain + html anchor, deduped, with context.
	urlSet := map[string]ExtractedURL{}
	for _, u := range pe.URLs {
		urlSet[u.URL] = u
	}
	if _, ok := urlSet["http://plain.example.com/invoice"]; !ok {
		t.Errorf("plain-text URL not extracted: %+v", pe.URLs)
	}
	anchor, ok := urlSet["https://html.example.com/pay"]
	if !ok {
		t.Fatalf("html anchor URL not extracted: %+v", pe.URLs)
	}
	if anchor.HTMLContext != "href" || anchor.VisibleText != "pay now" {
		t.Errorf("anchor context/visible = %q/%q, want href/'pay now'", anchor.HTMLContext, anchor.VisibleText)
	}

	// Attachment: hashed, sized, magic-byte detected as PDF, disposition set.
	if len(pe.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1", len(pe.Attachments))
	}
	att := pe.Attachments[0]
	if att.Filename != "invoice.pdf" {
		t.Errorf("attachment filename = %q, want invoice.pdf", att.Filename)
	}
	if att.SHA256 == "" || att.MD5 == "" || att.SHA1 == "" {
		t.Errorf("attachment hashes missing: %+v", att)
	}
	if att.DetectedType != "application/pdf" {
		t.Errorf("detected_type = %q, want application/pdf", att.DetectedType)
	}
	if att.ContentID != "att-1" {
		t.Errorf("content_id = %q, want att-1 (brackets stripped)", att.ContentID)
	}
	if att.Disposition != "attachment" {
		t.Errorf("disposition = %q, want attachment", att.Disposition)
	}
	if string(att.Data) != "%PDF-1.4 fake pdf bytes" {
		t.Errorf("attachment body not base64-decoded: %q", att.Data)
	}

	// Recipients: 2 To + 1 Cc, typed.
	if len(pe.Recipients) != 3 {
		t.Fatalf("got %d recipients, want 3: %+v", len(pe.Recipients), pe.Recipients)
	}
	var toCount, ccCount int
	for _, r := range pe.Recipients {
		switch r.Type {
		case "to":
			toCount++
		case "cc":
			ccCount++
		}
	}
	if toCount != 2 || ccCount != 1 {
		t.Errorf("recipient types: to=%d cc=%d, want 2/1", toCount, ccCount)
	}
}

func TestParseBodyCharsetAndSynthesisFlag(t *testing.T) {
	// Multipart with a genuine text/plain part: BodyCharset is captured from the
	// body part (S5) — the top-level multipart Content-Type carries no charset —
	// and PlainSynthesised is false because a real plain part exists (A1).
	pe, err := Parse(buildMIME())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pe.BodyCharset != "utf-8" {
		t.Errorf("BodyCharset = %q, want utf-8 (from the body part, not the empty top-level Content-Type)", pe.BodyCharset)
	}
	if pe.PlainSynthesised {
		t.Error("PlainSynthesised must be false when a genuine text/plain part exists")
	}

	// HTML-only message (no text/plain part): SVC-02 synthesises BodyPlain from the
	// HTML, so PlainSynthesised must be true and BodyCharset comes from the HTML part.
	raw := "From: a@b.com\r\n" +
		"Subject: hi\r\n" +
		"Content-Type: text/html; charset=\"iso-8859-1\"\r\n\r\n" +
		`<html><body><p>Pay now</p></body></html>` + "\r\n"
	pe, err = Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse html-only: %v", err)
	}
	if !pe.PlainSynthesised {
		t.Error("PlainSynthesised must be true for an HTML-only message")
	}
	if pe.BodyCharset != "iso-8859-1" {
		t.Errorf("BodyCharset = %q, want iso-8859-1", pe.BodyCharset)
	}
	if strings.TrimSpace(pe.BodyPlain) == "" {
		t.Error("BodyPlain should be synthesised from the HTML")
	}
}

func TestParseHeaderOnlyMessage(t *testing.T) {
	raw := "From: a@b.example\r\nSubject: hi\r\n\r\nplain body text\r\n"
	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if pe.Subject != "hi" {
		t.Errorf("subject = %q", pe.Subject)
	}
	if !strings.Contains(pe.BodyPlain, "plain body text") {
		t.Errorf("body_plain = %q", pe.BodyPlain)
	}
	if len(pe.Attachments) != 0 {
		t.Errorf("got %d attachments, want 0", len(pe.Attachments))
	}
}

// TestDecodeBodyMalformedBase64ReturnsOriginal guards the stripWhitespaceBytes
// aliasing bug: when a base64 part has interior whitespace but is malformed once
// stripped, decodeBody must hand back the ORIGINAL raw bytes unchanged — not a
// compacted prefix left behind by mutating the caller's backing array.
func TestDecodeBodyMalformedBase64ReturnsOriginal(t *testing.T) {
	// "ABCD@@@@" is not valid base64 (`@` is not in the alphabet); the embedded
	// spaces/newlines exercise stripWhitespaceBytes before the decode fails.
	raw := []byte("AB CD\r\n@@@@")
	original := append([]byte(nil), raw...) // independent copy of the input

	got := decodeBody(bytes.NewReader(raw), "base64")

	if !bytes.Equal(got, original) {
		t.Fatalf("decodeBody on malformed base64 = %q, want original %q", got, original)
	}
}

// TestParseTwoTextPlainPartsSeparated guards the body-concatenation bug: two
// text/plain leaves in one multipart/mixed container must be joined with a
// delimiter so a URL ending one part and a token starting the next are not
// glued into a fabricated URL (and the word count stays correct).
func TestParseTwoTextPlainPartsSeparated(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: a@b.example\r\n")
	b.WriteString("Subject: hi\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"MIX\"\r\n\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString("Hello visit https://good.example\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString("Unsubscribe here\r\n")
	b.WriteString("--MIX--\r\n")

	pe, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	urls := map[string]struct{}{}
	for _, u := range pe.URLs {
		urls[u.URL] = struct{}{}
	}
	if _, ok := urls["https://good.example"]; !ok {
		t.Errorf("legit URL not extracted intact, got URLs %+v", pe.URLs)
	}
	if _, ok := urls["https://good.exampleUnsubscribe"]; ok {
		t.Errorf("parts glued into fabricated URL: %+v", pe.URLs)
	}
	if got, want := WordCount(pe.BodyPlain), 5; got != want {
		t.Errorf("WordCount(body) = %d, want %d (body=%q)", got, want, pe.BodyPlain)
	}
}

// TestParseForwardedRFC822ExtractsInnerURLs guards that a phishing email
// forwarded as a message/rfc822 attachment has its inner body and URLs
// extracted and scored, rather than landing as an opaque attachment blob.
func TestParseForwardedRFC822ExtractsInnerURLs(t *testing.T) {
	inner := "From: phish@evil.example\r\n" +
		"Subject: account locked\r\n\r\n" +
		"Click http://evil.example/login to unlock.\r\n"

	var b strings.Builder
	b.WriteString("From: friend@corp.example\r\n")
	b.WriteString("Subject: Fwd: suspicious\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"MIX\"\r\n\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: text/plain\r\n\r\n")
	b.WriteString("Is this real?\r\n")
	b.WriteString("--MIX\r\n")
	b.WriteString("Content-Type: message/rfc822\r\n\r\n")
	b.WriteString(inner)
	b.WriteString("--MIX--\r\n")

	pe, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	found := false
	for _, u := range pe.URLs {
		if u.URL == "http://evil.example/login" {
			found = true
		}
	}
	if !found {
		t.Errorf("inner forwarded URL not extracted, got URLs %+v / attachments %d", pe.URLs, len(pe.Attachments))
	}
	if !strings.Contains(pe.BodyPlain, "Click") {
		t.Errorf("inner forwarded body not merged: %q", pe.BodyPlain)
	}
}

// TestHasTextSubjectOnly guards that a subject-only (body-less) message still
// reports HasText() true so the analysis plan declares the NLP topic and the
// subject-only NLP score is not dropped from the fusion verdict.
func TestHasTextSubjectOnly(t *testing.T) {
	subjOnly := &ParsedEmail{Subject: "Your account is locked, call this number"}
	if subjOnly.HasBody() {
		t.Error("HasBody() = true for body-less message, want false")
	}
	if !subjOnly.HasText() {
		t.Error("HasText() = false for subject-only message, want true")
	}

	empty := &ParsedEmail{}
	if empty.HasText() {
		t.Error("HasText() = true for empty message, want false")
	}
}

func TestParseAuthResults(t *testing.T) {
	got := ParseAuthResults("mx.example; spf=pass smtp.mailfrom=x; dkim=fail; dmarc=softfail; arc=none")
	want := map[string]string{"spf": "pass", "dkim": "fail", "dmarc": "softfail", "arc": "none"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("auth[%q] = %q, want %q", k, got[k], v)
		}
	}
	if len(ParseAuthResults("")) != 0 {
		t.Error("empty input should yield empty map")
	}
}
