package email

import (
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
