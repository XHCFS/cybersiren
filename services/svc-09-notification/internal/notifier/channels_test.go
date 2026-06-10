package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saif/cybersiren/shared/config"
)

func sampleAlert() Alert {
	camp := int64(42)
	return Alert{
		OrgID:        7,
		EmailID:      1234,
		InternalID:   9,
		VerdictLabel: "phishing",
		RiskScore:    88,
		Confidence:   0.9,
		CampaignID:   &camp,
		IssuedAt:     time.Unix(0, 0).UTC(),
		Recipients:   []string{"admin@acme.test"},
	}
}

func TestBuildChannels_OnlyEnabled(t *testing.T) {
	t.Parallel()
	// Default config: both disabled -> empty set, no startup requirement.
	if ch := BuildChannels(config.NotificationConfig{}); len(ch) != 0 {
		t.Fatalf("default config produced %d channels, want 0", len(ch))
	}

	cfg := config.NotificationConfig{
		SMTP:    config.SMTPConfig{Enabled: true, Host: "h", Port: 25, From: "a@b.c"},
		Webhook: config.WebhookConfig{Enabled: false, URL: "https://x"},
	}
	ch := BuildChannels(cfg)
	if _, ok := ch[ChannelEmail]; !ok {
		t.Error("email channel should be built when SMTP enabled")
	}
	if _, ok := ch[ChannelWebhook]; ok {
		t.Error("webhook channel should NOT be built when disabled")
	}
}

func TestWebhookChannel_PostsSignedJSON(t *testing.T) {
	t.Parallel()
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := "s3cr3t"
	ch := NewWebhookChannel(config.WebhookConfig{URL: srv.URL, Secret: secret, Timeout: 2 * time.Second})
	if err := ch.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var got Alert
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("server got non-JSON body: %v", err)
	}
	if got.RiskScore != 88 || got.VerdictLabel != "phishing" {
		t.Errorf("webhook payload = %+v, want risk 88 phishing", got)
	}
	// Admin recipients must not leak to the external webhook.
	if len(got.Recipients) != 0 {
		t.Errorf("webhook payload leaked recipients: %v", got.Recipients)
	}
	// Signature must verify against the exact transmitted body.
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("X-Signature = %q, want %q", gotSig, want)
	}
}

func TestWebhookChannel_RetriesOnFailure(t *testing.T) {
	t.Parallel()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(config.WebhookConfig{URL: srv.URL, Timeout: 2 * time.Second, MaxRetries: 3})
	if err := ch.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send should succeed on the 3rd attempt: %v", err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Errorf("server hit %d times, want 3", calls)
	}
}

func TestWebhookChannel_ErrorsAfterRetries(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(config.WebhookConfig{URL: srv.URL, Timeout: time.Second, MaxRetries: 1})
	if err := ch.Send(context.Background(), sampleAlert()); err == nil {
		t.Fatal("expected error when every attempt fails")
	}
}

func TestEmailChannel_BuildsAndSends(t *testing.T) {
	t.Parallel()
	var gotFrom string
	var gotTo []string
	var gotMsg []byte
	ch := NewEmailChannel(config.SMTPConfig{
		Host: "smtp.test", Port: 587, From: "alerts@cybersiren.test",
		Username: "u", Password: "p",
	})
	ch.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		if addr != "smtp.test:587" {
			t.Errorf("addr = %q, want smtp.test:587", addr)
		}
		if auth == nil {
			t.Error("expected PLAIN auth when username set")
		}
		gotFrom, gotTo, gotMsg = from, to, msg
		return nil
	}

	if err := ch.Send(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotFrom != "alerts@cybersiren.test" {
		t.Errorf("from = %q", gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "admin@acme.test" {
		t.Errorf("to = %v, want [admin@acme.test]", gotTo)
	}
	body := string(gotMsg)
	for _, want := range []string{"Subject:", "phishing", "Risk score:  88", "admin@acme.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("message missing %q\n---\n%s", want, body)
		}
	}
}

func TestEmailChannel_NoRecipientsIsNoOp(t *testing.T) {
	t.Parallel()
	ch := NewEmailChannel(config.SMTPConfig{Host: "h", Port: 25, From: "a@b.c"})
	called := false
	ch.send = func(string, smtp.Auth, string, []string, []byte) error {
		called = true
		return nil
	}
	a := sampleAlert()
	a.Recipients = nil
	if err := ch.Send(context.Background(), a); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if called {
		t.Error("SMTP send should not be called with zero recipients")
	}
}
