package campaign

import (
	"encoding/json"
	"strings"
	"testing"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestFingerprint_DeterministicAndCanonicalised(t *testing.T) {
	a := Fingerprint(Inputs{
		SenderDomain: "EVIL.COM",
		URLDomain:    "Phishing-Site.io",
		Subject:      "Re: Your invoice 1234567",
		Intent:       "PHISHING",
	})
	b := Fingerprint(Inputs{
		SenderDomain: "evil.com",
		URLDomain:    "phishing-site.io",
		Subject:      "your invoice {n}",
		Intent:       "phishing",
	})
	if a != b {
		t.Fatalf("fingerprint not canonical:\n a=%s\n b=%s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(a))
	}
}

func TestNormaliseSubject(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Re: Your order ABC1234567", "your order abc{n}"},
		{"Fwd: ORDER-1234567", "order-{n}"},
		{"[EXTERNAL] Re: Action required for 550e8400-e29b-41d4-a716-446655440000",
			"action required for {uuid}"},
		{"Reply to alice@example.com now", "reply to {email} now"},
		{"   Spaces preserved minus prefix", "spaces preserved minus prefix"},
	}
	for _, tt := range tests {
		got := normaliseSubject(tt.in)
		if got != tt.want {
			t.Errorf("normaliseSubject(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractInputs_FromComponentDetails(t *testing.T) {
	header := mustJSON(map[string]any{
		"signals": map[string]any{
			"sender_domain": "evil.example.com",
			"subject":       "ALERT: invoice 12345",
		},
	})
	urlMsg := mustJSON(map[string]any{
		"details": map[string]any{
			"per_url": []map[string]any{
				{"url": "https://www.phish.example/signin", "score": 92},
				{"url": "https://benign.example/", "score": 5},
			},
		},
	})
	nlp := mustJSON(map[string]any{
		"details": map[string]any{
			"intent_labels": []string{"phishing", "urgency"},
			"plain_text":    "click here to verify",
		},
	})

	in := ExtractInputs(contracts.ComponentDetails{
		Header: header,
		URL:    urlMsg,
		NLP:    nlp,
	})

	if in.SenderDomain != "evil.example.com" {
		t.Errorf("sender_domain = %q, want evil.example.com", in.SenderDomain)
	}
	if in.URLDomain != "phish.example" {
		t.Errorf("url_domain = %q, want phish.example", in.URLDomain)
	}
	if !strings.Contains(strings.ToLower(in.Subject), "invoice") {
		t.Errorf("subject = %q, expected to contain 'invoice'", in.Subject)
	}
	if in.Intent != "phishing" {
		t.Errorf("intent = %q, want phishing", in.Intent)
	}
}

func TestExtractBody(t *testing.T) {
	d := contracts.ComponentDetails{
		NLP: mustJSON(map[string]any{
			"details": map[string]any{
				"plain_text": "  Click HERE to confirm  ",
				"subject":    "Reset password",
			},
		}),
	}
	body, ok := ExtractBody(d)
	if !ok {
		t.Fatalf("ExtractBody() ok=false")
	}
	if !strings.Contains(body, "click here") {
		t.Errorf("ExtractBody() = %q, expected to contain 'click here'", body)
	}
	if !strings.Contains(body, "reset password") {
		t.Errorf("ExtractBody() = %q, expected to contain 'reset password'", body)
	}
}

func TestExtractBody_EmptyReturnsFalse(t *testing.T) {
	if _, ok := ExtractBody(contracts.ComponentDetails{}); ok {
		t.Fatalf("ExtractBody() on empty details: ok=true, want false")
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
