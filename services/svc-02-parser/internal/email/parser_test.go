package email

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseNestedMultipart(t *testing.T) {
	raw := "From: alice@example.com\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: nested\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=OUTER\r\n" +
		"\r\n" +
		"--OUTER\r\n" +
		"Content-Type: multipart/alternative; boundary=INNER\r\n" +
		"\r\n" +
		"--INNER\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"plain body text\r\n" +
		"--INNER\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<p>html body</p>\r\n" +
		"--INNER--\r\n" +
		"--OUTER--\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(pe.BodyPlain, "plain body text") {
		t.Errorf("BodyPlain = %q, want it to contain plain body text", pe.BodyPlain)
	}
	if !strings.Contains(pe.BodyHTML, "html body") {
		t.Errorf("BodyHTML = %q, want it to contain html body", pe.BodyHTML)
	}
}

func TestParseQuotedPrintableBody(t *testing.T) {
	raw := "From: a@example.com\r\n" +
		"Subject: qp\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"price is 100=E2=82=AC today=\r\n" +
		" and more\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(pe.BodyPlain, "100€") {
		t.Errorf("BodyPlain = %q, want decoded euro sign", pe.BodyPlain)
	}
	if !strings.Contains(pe.BodyPlain, "today and more") {
		t.Errorf("BodyPlain = %q, want soft line break removed", pe.BodyPlain)
	}
}

func TestParseBase64Body(t *testing.T) {
	payload := "secret base64 body"
	raw := "From: a@example.com\r\n" +
		"Subject: b64\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString([]byte(payload)) + "\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(pe.BodyPlain, payload) {
		t.Errorf("BodyPlain = %q, want decoded %q", pe.BodyPlain, payload)
	}
}

func TestParseAttachmentHashesAndType(t *testing.T) {
	pdf := []byte("%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
	wantSHA := sha256.Sum256(pdf)

	raw := "From: a@example.com\r\n" +
		"Subject: with attachment\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=BB\r\n" +
		"\r\n" +
		"--BB\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"see attached\r\n" +
		"--BB\r\n" +
		"Content-Type: application/octet-stream; name=\"invoice.pdf\"\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString(pdf) + "\r\n" +
		"--BB--\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pe.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1", len(pe.Attachments))
	}
	a := pe.Attachments[0]
	if a.SHA256 != hex.EncodeToString(wantSHA[:]) {
		t.Errorf("SHA256 = %s, want %s (base64 must be decoded before hashing)", a.SHA256, hex.EncodeToString(wantSHA[:]))
	}
	if len(a.MD5) != 32 || len(a.SHA1) != 40 {
		t.Errorf("MD5 len %d, SHA1 len %d; want 32 and 40", len(a.MD5), len(a.SHA1))
	}
	if a.ActualExtension != "pdf" {
		t.Errorf("ActualExtension = %q, want pdf (magic-byte detection)", a.ActualExtension)
	}
	if a.Filename != "invoice.pdf" {
		t.Errorf("Filename = %q, want invoice.pdf", a.Filename)
	}
	if a.SizeBytes != int64(len(pdf)) {
		t.Errorf("SizeBytes = %d, want %d", a.SizeBytes, len(pdf))
	}
	if a.Entropy <= 0 {
		t.Errorf("Entropy = %v, want > 0", a.Entropy)
	}
}

func TestParseRecipients(t *testing.T) {
	raw := "From: a@example.com\r\n" +
		"To: Bob <bob@example.org>, carol@example.org\r\n" +
		"Cc: dave@example.net\r\n" +
		"Bcc: eve@example.io\r\n" +
		"Subject: recips\r\n" +
		"\r\n" +
		"body\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	counts := map[string]int{}
	for _, r := range pe.Recipients {
		counts[r.Type]++
	}
	if counts["to"] != 2 || counts["cc"] != 1 || counts["bcc"] != 1 {
		t.Errorf("recipient counts = %v, want to=2 cc=1 bcc=1", counts)
	}
}

func TestShannonEntropyBounds(t *testing.T) {
	if e := shannonEntropy(nil); e != 0 {
		t.Errorf("entropy(nil) = %v, want 0", e)
	}
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	if e := shannonEntropy(uniform); e < 7.99 || e > 8.0 {
		t.Errorf("entropy(uniform 0..255) = %v, want ~8.0", e)
	}
}
