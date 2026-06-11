package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/saif/cybersiren/shared/config"
)

// Channel is one alert transport. Send delivers a single alert; it returns an
// error to signal a transient failure (the notifier counts it but does not
// NACK the Kafka message on a channel failure — an alert is best-effort).
type Channel interface {
	// Name is the metric/label name for this channel ("email"|"webhook").
	Name() string
	// Send delivers the alert. Implementations must respect ctx deadlines.
	Send(ctx context.Context, a Alert) error
}

// -----------------------------------------------------------------------------
// Webhook channel
// -----------------------------------------------------------------------------

// WebhookChannel POSTs the alert as JSON to a SIEM/SOAR endpoint. It is only
// constructed when cfg.Enabled is true (see BuildChannels), so the notifier
// never holds a webhook channel for a deployment that has not configured one.
type WebhookChannel struct {
	cfg    config.WebhookConfig
	client *http.Client
}

// NewWebhookChannel builds a webhook sender from the (enabled) config.
func NewWebhookChannel(cfg config.WebhookConfig) *WebhookChannel {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WebhookChannel{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}
}

func (w *WebhookChannel) Name() string { return ChannelWebhook }

func (w *WebhookChannel) Send(ctx context.Context, a Alert) error {
	// Recipients are an email-channel concern; do not leak admin addresses to
	// an external SIEM/SOAR webhook.
	payload := a
	payload.Recipients = nil

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	attempts := w.cfg.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			// Bounded backoff so a flapping endpoint is not hammered with
			// zero-delay retries. Caps at webhookMaxBackoff; respects ctx.
			if err := sleepCtx(ctx, webhookBackoff(i)); err != nil {
				return err
			}
		}
		lastErr = w.post(ctx, body)
		if lastErr == nil {
			return nil
		}
		// A 4xx is a permanent client error (a misconfigured/unauthorised
		// endpoint): retrying cannot fix it and only wastes the rate-limit
		// window + the endpoint's attention, so stop immediately. Transport
		// errors and 5xx remain retryable.
		if errors.Is(lastErr, errPermanentWebhook) {
			return fmt.Errorf("webhook POST: %w", lastErr)
		}
	}
	return fmt.Errorf("webhook POST failed after %d attempt(s): %w", attempts, lastErr)
}

// errPermanentWebhook marks a non-retryable webhook failure (a 4xx response).
var errPermanentWebhook = errors.New("permanent webhook error")

func (w *WebhookChannel) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cybersiren-svc-09-notification")
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w: webhook returned status %d", errPermanentWebhook, resp.StatusCode)
	default:
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
}

// webhookBaseBackoff is the first retry delay; subsequent retries grow it
// exponentially, capped at webhookMaxBackoff.
const (
	webhookBaseBackoff = 100 * time.Millisecond
	webhookMaxBackoff  = 2 * time.Second
)

// webhookBackoff returns the delay before retry attempt i (i>=1): base*2^(i-1)
// clamped to webhookMaxBackoff.
func webhookBackoff(i int) time.Duration {
	d := webhookBaseBackoff
	for n := 1; n < i; n++ {
		d *= 2
		if d >= webhookMaxBackoff {
			return webhookMaxBackoff
		}
	}
	if d > webhookMaxBackoff {
		return webhookMaxBackoff
	}
	return d
}

// sleepCtx blocks for d or until ctx is cancelled, whichever comes first. It
// returns ctx.Err() on cancellation so a flapping-endpoint retry loop can bail
// promptly when the consumer is shutting down.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// -----------------------------------------------------------------------------
// Email (SMTP) channel
// -----------------------------------------------------------------------------

// smtpSender abstracts the SMTP round-trip so the email channel is unit
// testable without a live relay. The production implementation dials with an
// explicit deadline and honours cfg.Timeout / cfg.StartTLS (see sendSMTP);
// channels_test.go injects a fake with this same signature.
type smtpSender func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error

// EmailChannel sends alert emails to the org's admin contacts over SMTP. It is
// only constructed when cfg.Enabled is true.
type EmailChannel struct {
	cfg  config.SMTPConfig
	send smtpSender
}

// NewEmailChannel builds an SMTP email sender from the (enabled) config. The
// default sender dials with cfg.Timeout and only performs STARTTLS when
// cfg.StartTLS is set (an implicit-TLS dial is used otherwise, typical for
// port 465), unlike net/smtp.SendMail which has no deadline and always
// auto-negotiates STARTTLS.
func NewEmailChannel(cfg config.SMTPConfig) *EmailChannel {
	e := &EmailChannel{cfg: cfg}
	e.send = e.sendSMTP
	return e
}

func (e *EmailChannel) Name() string { return ChannelEmail }

func (e *EmailChannel) Send(ctx context.Context, a Alert) error {
	if len(a.Recipients) == 0 {
		// No admin contacts to address — not an error, just nothing to do.
		// The caller (notifier.dispatch) treats this as a no-recipients skip,
		// not a delivered alert.
		return errNoRecipients
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)
	var auth smtp.Auth
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
	}
	msg := e.buildMessage(a)
	if err := e.send(addr, auth, e.cfg.From, a.Recipients, msg); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// errNoRecipients signals a gated alert that had no admin recipient to address.
// It is not a delivery failure; the caller maps it to a "no_recipients" skip so
// the alert metric stays honest (no phantom "sent").
var errNoRecipients = errors.New("notifier: no email recipients")

// sendSMTP is the production smtpSender. It dials with an explicit deadline so
// cfg.Timeout actually bounds the connect+send round-trip, and performs
// STARTTLS only when cfg.StartTLS is set; when StartTLS is false it dials
// implicit TLS (typical for port 465). cfg.Timeout is validated > 0 for an
// enabled channel, but a non-positive value is defended here for direct
// construction in tests.
func (e *EmailChannel) sendSMTP(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	timeout := e.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var conn net.Conn
	var err error
	if e.cfg.StartTLS {
		// Plaintext dial; upgrade to TLS via STARTTLS below.
		conn, err = net.DialTimeout("tcp", addr, timeout)
	} else {
		// Implicit TLS (e.g. port 465): the whole connection is TLS from the
		// first byte, so no STARTTLS upgrade is attempted.
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: e.cfg.Host})
	}
	if err != nil {
		return fmt.Errorf("dial smtp %s: %w", addr, err)
	}
	// Compute the round-trip deadline only after the dial returns so a slow
	// connect (which already has its own DialTimeout/dialer.Timeout) does not
	// cannibalise the budget for the EHLO/STARTTLS/MAIL/RCPT/DATA round-trip.
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = c.Close() }()

	if e.cfg.StartTLS {
		// Fail closed: if STARTTLS is required but the server does not advertise
		// it, abort rather than silently transmitting credentials and the
		// message body in cleartext.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("starttls required but not advertised by %s", addr)
		}
		if err := c.StartTLS(&tls.Config{ServerName: e.cfg.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

func (e *EmailChannel) buildMessage(a Alert) []byte {
	var b strings.Builder
	subject := fmt.Sprintf("[CyberSiren] %s alert — risk %d", strings.ToUpper(a.VerdictLabel), a.RiskScore)
	fmt.Fprintf(&b, "From: %s\r\n", e.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(a.Recipients, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "A phishing-detection verdict crossed your alert threshold.\r\n\r\n")
	fmt.Fprintf(&b, "Verdict:     %s\r\n", a.VerdictLabel)
	fmt.Fprintf(&b, "Risk score:  %d/100\r\n", a.RiskScore)
	fmt.Fprintf(&b, "Confidence:  %.2f\r\n", a.Confidence)
	fmt.Fprintf(&b, "Email ID:    %d\r\n", a.EmailID)
	if a.CampaignID != nil {
		fmt.Fprintf(&b, "Campaign ID: %d\r\n", *a.CampaignID)
	}
	fmt.Fprintf(&b, "Issued at:   %s\r\n", a.IssuedAt.Format(time.RFC3339))
	return []byte(b.String())
}

// BuildChannels constructs the channel set from the notification config. Only
// channels whose Enabled flag is set are built, so a deployment that has not
// configured SMTP or the webhook simply gets a shorter (possibly empty)
// channel set — SVC-09 never hard-requires either transport at startup. The
// returned map is keyed by channel name (ChannelEmail / ChannelWebhook).
func BuildChannels(cfg config.NotificationConfig) map[string]Channel {
	channels := map[string]Channel{}
	if cfg.SMTP.Enabled {
		channels[ChannelEmail] = NewEmailChannel(cfg.SMTP)
	}
	if cfg.Webhook.Enabled {
		channels[ChannelWebhook] = NewWebhookChannel(cfg.Webhook)
	}
	return channels
}
