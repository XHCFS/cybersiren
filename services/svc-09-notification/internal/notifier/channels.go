package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
		lastErr = w.post(ctx, body)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("webhook POST failed after %d attempt(s): %w", attempts, lastErr)
}

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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Email (SMTP) channel
// -----------------------------------------------------------------------------

// smtpSender abstracts the SMTP round-trip so the email channel is unit
// testable without a live relay. The production implementation calls
// net/smtp.SendMail.
type smtpSender func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error

// EmailChannel sends alert emails to the org's admin contacts over SMTP. It is
// only constructed when cfg.Enabled is true.
type EmailChannel struct {
	cfg  config.SMTPConfig
	send smtpSender
}

// NewEmailChannel builds an SMTP email sender from the (enabled) config.
func NewEmailChannel(cfg config.SMTPConfig) *EmailChannel {
	return &EmailChannel{cfg: cfg, send: smtp.SendMail}
}

func (e *EmailChannel) Name() string { return ChannelEmail }

func (e *EmailChannel) Send(ctx context.Context, a Alert) error {
	if len(a.Recipients) == 0 {
		// No admin contacts to address — not an error, just nothing to do.
		return nil
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
