package notifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
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

func TestEmailChannel_NoRecipientsSkips(t *testing.T) {
	t.Parallel()
	ch := NewEmailChannel(config.SMTPConfig{Host: "h", Port: 25, From: "a@b.c"})
	called := false
	ch.send = func(string, smtp.Auth, string, []string, []byte) error {
		called = true
		return nil
	}
	a := sampleAlert()
	a.Recipients = nil
	// A zero-recipient send must not hit the relay and must signal a
	// no-recipients skip (not a delivery, not a transient failure) so the
	// caller can keep the metric honest.
	err := ch.Send(context.Background(), a)
	if !errors.Is(err, errNoRecipients) {
		t.Fatalf("Send err = %v, want errNoRecipients", err)
	}
	if called {
		t.Error("SMTP send should not be called with zero recipients")
	}
}

// fakeSMTPServer is a tiny plaintext SMTP responder that drives the real
// net/smtp client through EHLO/MAIL/RCPT/DATA/QUIT and records whether the
// client attempted STARTTLS and whether it issued any mail-transfer command
// (MAIL/RCPT/DATA) in cleartext. By default it advertises STARTTLS so the
// client is free to upgrade; set noStartTLS to suppress the capability and
// exercise the fail-closed path (F6).
type fakeSMTPServer struct {
	ln          net.Listener
	addr        string
	noStartTLS  bool // when true, EHLO does not advertise STARTTLS
	gotStartTLS atomic.Bool
	gotMail     atomic.Bool // any MAIL/RCPT/DATA seen -> cleartext transmission happened
	done        chan struct{}
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	return startFakeSMTPServer(t, false)
}

// startFakeSMTPServer starts a fake SMTP server; noStartTLS controls whether the
// EHLO response advertises the STARTTLS capability.
func startFakeSMTPServer(t *testing.T, noStartTLS bool) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{ln: ln, addr: ln.Addr().String(), noStartTLS: noStartTLS, done: make(chan struct{})}
	go s.serve()
	return s
}

func (s *fakeSMTPServer) serve() {
	defer close(s.done)
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := newLineReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s)) }

	write("220 fake ESMTP\r\n")
	for {
		line, err := br()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if s.noStartTLS {
				// Advertise no extensions: the client must fail closed rather
				// than fall back to cleartext when StartTLS is required.
				write("250 fake greets you\r\n")
			} else {
				write("250-fake greets you\r\n250 STARTTLS\r\n")
			}
		case strings.HasPrefix(cmd, "STARTTLS"):
			s.gotStartTLS.Store(true)
			// Refuse the upgrade so the client aborts deterministically without
			// needing a real TLS cert; the test only checks the attempt flag.
			write("454 TLS not available\r\n")
			return
		case strings.HasPrefix(cmd, "MAIL"):
			s.gotMail.Store(true)
			write("250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT"):
			s.gotMail.Store(true)
			write("250 OK\r\n")
		case strings.HasPrefix(cmd, "DATA"):
			s.gotMail.Store(true)
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
			// Consume the message body until the lone "." terminator.
			for {
				l, err := br()
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			write("250 OK\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			write("221 Bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

func (s *fakeSMTPServer) close() { _ = s.ln.Close() }

// newLineReader returns a function that reads one CRLF-terminated line from r.
func newLineReader(r net.Conn) func() (string, error) {
	buf := make([]byte, 0, 256)
	one := make([]byte, 1)
	return func() (string, error) {
		buf = buf[:0]
		for {
			n, err := r.Read(one)
			if n > 0 {
				buf = append(buf, one[0])
				if one[0] == '\n' {
					return string(buf), nil
				}
			}
			if err != nil {
				if len(buf) > 0 {
					return string(buf), nil
				}
				return "", err
			}
		}
	}
}

func TestEmailChannel_StartTLSAttemptedWhenEnabled(t *testing.T) {
	t.Parallel()
	srv := newFakeSMTPServer(t)
	defer srv.close()
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port := atoiOrFail(t, portStr)

	ch := NewEmailChannel(config.SMTPConfig{
		Host: host, Port: port, From: "a@b.c",
		StartTLS: true, Timeout: 3 * time.Second,
	})
	// The fake refuses the TLS upgrade, so Send returns an error — but the
	// point under test is that the client ATTEMPTED STARTTLS.
	_ = ch.Send(context.Background(), sampleAlert())
	<-srv.done
	if !srv.gotStartTLS.Load() {
		t.Error("StartTLS=true should make the client attempt STARTTLS")
	}
}

// TestEmailChannel_StartTLSRequiredButNotAdvertised covers the F6 fail-closed
// fix: when cfg.StartTLS is true but the server does not advertise STARTTLS,
// Send must return an error and must NOT transmit the message in cleartext
// (no MAIL/RCPT/DATA issued).
func TestEmailChannel_StartTLSRequiredButNotAdvertised(t *testing.T) {
	t.Parallel()
	srv := startFakeSMTPServer(t, true) // does NOT advertise STARTTLS
	defer srv.close()
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port := atoiOrFail(t, portStr)

	ch := NewEmailChannel(config.SMTPConfig{
		Host: host, Port: port, From: "a@b.c",
		StartTLS: true, Timeout: 3 * time.Second,
	})
	err := ch.Send(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("StartTLS required but not advertised: Send must fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "starttls required but not advertised") {
		t.Errorf("error = %v, want a 'starttls required but not advertised' failure", err)
	}
	srv.close()
	<-srv.done
	if srv.gotStartTLS.Load() {
		t.Error("client must not issue STARTTLS when the server never advertised it")
	}
	if srv.gotMail.Load() {
		t.Error("fail-closed path leaked a cleartext MAIL/RCPT/DATA command")
	}
}

func TestEmailChannel_StartTLSSkippedWhenDisabled(t *testing.T) {
	t.Parallel()
	srv := newFakeSMTPServer(t)
	defer srv.close()
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port := atoiOrFail(t, portStr)

	// StartTLS=false on a plaintext server: the production sender dials implicit
	// TLS, which will fail the handshake against this plaintext listener — but
	// crucially it must NOT issue a plaintext STARTTLS command.
	ch := NewEmailChannel(config.SMTPConfig{
		Host: host, Port: port, From: "a@b.c",
		StartTLS: false, Timeout: 3 * time.Second,
	})
	_ = ch.Send(context.Background(), sampleAlert())
	srv.close()
	<-srv.done
	if srv.gotStartTLS.Load() {
		t.Error("StartTLS=false must not issue a STARTTLS command")
	}
}

func TestEmailChannel_DialHonorsTimeout(t *testing.T) {
	t.Parallel()
	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737), guaranteed non-routable, so the
	// TCP connect blocks until our deadline fires rather than RST-ing fast.
	ch := NewEmailChannel(config.SMTPConfig{
		Host: "203.0.113.1", Port: 25, From: "a@b.c",
		StartTLS: true, Timeout: 150 * time.Millisecond,
	})
	start := time.Now()
	err := ch.Send(context.Background(), sampleAlert())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected a dial timeout error")
	}
	// Must give up close to the configured timeout, not block indefinitely or
	// wait for the OS default (~tens of seconds).
	if elapsed > 3*time.Second {
		t.Errorf("dial took %v, want bounded by ~150ms timeout", elapsed)
	}
}

func atoiOrFail(t *testing.T, s string) int {
	t.Helper()
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("non-numeric port %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func TestWebhookChannel_RetryBackoffRespectsContext(t *testing.T) {
	t.Parallel()
	// Endpoint always fails; with MaxRetries>0 the backoff loop runs, but a
	// cancelled ctx must abort it promptly instead of sleeping out every delay.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(config.WebhookConfig{URL: srv.URL, Timeout: time.Second, MaxRetries: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := ch.Send(ctx, sampleAlert()); err == nil {
		t.Fatal("expected an error when ctx is cancelled during backoff")
	}
	// 5 retries at >=100ms each would be >=500ms without ctx-aware backoff.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("retry loop took %v; backoff should bail on ctx cancellation", elapsed)
	}
}

func TestWebhookChannel_DoesNotRetry4xx(t *testing.T) {
	t.Parallel()
	// A 4xx is a permanent client error (a misconfigured/unauthorised endpoint):
	// the shared httputil client retries only 429/5xx/transport errors, NOT 4xx —
	// unlike the old bespoke loop which retried every non-2xx. The endpoint must
	// be hit exactly once and Send must still error.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ch := NewWebhookChannel(config.WebhookConfig{URL: srv.URL, Timeout: time.Second, MaxRetries: 3})
	if err := ch.Send(context.Background(), sampleAlert()); err == nil {
		t.Fatal("expected an error on a 4xx webhook response")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("endpoint hit %d times, want 1 (4xx must not be retried)", got)
	}
}
