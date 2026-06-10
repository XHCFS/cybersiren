package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/smtp"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/shared/config"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

// --- fakes ------------------------------------------------------------------

type fakeOrgReader struct {
	prefs OrgPrefs
	err   error
}

func (f *fakeOrgReader) Load(context.Context, int64) (OrgPrefs, error) {
	return f.prefs, f.err
}

type fakeChannel struct {
	mu    sync.Mutex
	name  string
	sends []Alert
	err   error
}

func (c *fakeChannel) Name() string { return c.name }

func (c *fakeChannel) Send(_ context.Context, a Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.sends = append(c.sends, a)
	return nil
}

func (c *fakeChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sends)
}

func msgFor(v contracts.EmailsVerdict) kafkaconsumer.Message {
	b, _ := json.Marshal(v)
	return kafkaconsumer.Message{Value: b}
}

func prefsWith(threshold int, channels ...string) OrgPrefs {
	set := map[string]struct{}{}
	for _, c := range channels {
		set[c] = struct{}{}
	}
	return OrgPrefs{OrgID: 7, Threshold: threshold, Channels: set, AdminEmails: []string{"a@b.c"}}
}

func newVerdict() contracts.EmailsVerdict {
	v := contracts.EmailsVerdict{RiskScore: 90, VerdictLabel: "phishing"}
	v.Meta.OrgID = 7
	v.Meta.EmailID = 100
	return v
}

// --- tests ------------------------------------------------------------------

func TestHandle_GatedVerdictDispatches(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)

	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if webhook.count() != 1 {
		t.Fatalf("webhook sends = %d, want 1", webhook.count())
	}
}

func TestHandle_BelowGateNoDispatch(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	v := newVerdict()
	v.RiskScore = 30
	v.VerdictLabel = "suspicious"

	if err := n.Handle(context.Background(), msgFor(v)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if webhook.count() != 0 {
		t.Fatalf("webhook sends = %d, want 0 (below gate)", webhook.count())
	}
}

func TestHandle_RateLimitSuppressesSecond(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	camp := int64(5)
	v := newVerdict()
	v.CampaignID = &camp

	for i := 0; i < 3; i++ {
		if err := n.Handle(context.Background(), msgFor(v)); err != nil {
			t.Fatalf("Handle #%d: %v", i, err)
		}
	}
	if webhook.count() != 1 {
		t.Fatalf("webhook sends = %d, want 1 (rate limited to one per campaign)", webhook.count())
	}
}

func TestHandle_RateLimiterErrorFailsOpen(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook}
	limiter := newFakeLimiter()
	limiter.err = errors.New("redis down")
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		limiter,
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if webhook.count() != 1 {
		t.Fatalf("webhook sends = %d, want 1 (fail-open on limiter error)", webhook.count())
	}
}

func TestHandle_NilLimiterAllows(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		nil, // no limiter wired
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if webhook.count() != 1 {
		t.Fatalf("webhook sends = %d, want 1", webhook.count())
	}
}

func TestHandle_OnlyEnabledChannelsFire(t *testing.T) {
	t.Parallel()
	email := &fakeChannel{name: ChannelEmail}
	webhook := &fakeChannel{name: ChannelWebhook}
	// Org enables webhook only; both channels are configured in the deployment.
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelEmail: email, ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if webhook.count() != 1 {
		t.Errorf("webhook sends = %d, want 1", webhook.count())
	}
	if email.count() != 0 {
		t.Errorf("email sends = %d, want 0 (org did not enable email)", email.count())
	}
}

func TestHandle_OrgNotFoundCommits(t *testing.T) {
	t.Parallel()
	n := New(
		&fakeOrgReader{err: ErrOrgNotFound},
		newFakeLimiter(),
		map[string]Channel{},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("org-not-found should commit (nil err), got %v", err)
	}
}

func TestHandle_OrgLoadTransientErrorNACKs(t *testing.T) {
	t.Parallel()
	n := New(
		&fakeOrgReader{err: errors.New("connection reset")},
		newFakeLimiter(),
		map[string]Channel{},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err == nil {
		t.Fatal("transient org-load error should NACK (non-nil err)")
	}
}

func TestHandle_MalformedMessageCommits(t *testing.T) {
	t.Parallel()
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), kafkaconsumer.Message{Value: []byte("{not json")}); err != nil {
		t.Fatalf("malformed message should commit (nil err), got %v", err)
	}
}

func TestHandle_ChannelSendFailureDoesNotNACK(t *testing.T) {
	t.Parallel()
	webhook := &fakeChannel{name: ChannelWebhook, err: errors.New("smtp/webhook down")}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		NewMetrics(nil),
		zerolog.Nop(),
	)
	// A send failure is best-effort: the offset must still commit (nil err).
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("channel failure should not NACK, got %v", err)
	}
}

// outcome reads the notification_messages_total counter for a given outcome.
func outcome(m *Metrics, v string) float64 {
	return testutil.ToFloat64(m.MessagesTotal.WithLabelValues(v))
}

// alertResult reads notification_alerts_total for a channel+result pair.
func alertResult(m *Metrics, channel, result string) float64 {
	return testutil.ToFloat64(m.AlertsTotal.WithLabelValues(channel, result))
}

func TestHandle_DeliveredBumpsGatedOutcome(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := outcome(m, OutcomeGated); got != 1 {
		t.Errorf("outcome gated = %v, want 1", got)
	}
	if got := outcome(m, OutcomeGatedUndelivered); got != 0 {
		t.Errorf("outcome gated_undelivered = %v, want 0", got)
	}
	if got := alertResult(m, ChannelWebhook, AlertSent); got != 1 {
		t.Errorf("alert webhook/sent = %v, want 1", got)
	}
}

func TestHandle_NoChannelDeliveredBumpsGatedUndelivered(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	// Org enables webhook, but this deployment configured NO channels: gate
	// passes, rate limit passes, nothing fires. Must be a metric, not a log.
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := outcome(m, OutcomeGatedUndelivered); got != 1 {
		t.Errorf("outcome gated_undelivered = %v, want 1", got)
	}
	if got := outcome(m, OutcomeGated); got != 0 {
		t.Errorf("outcome gated = %v, want 0 (nothing delivered)", got)
	}
}

func TestHandle_AllChannelsFailBumpsGatedUndelivered(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	webhook := &fakeChannel{name: ChannelWebhook, err: errors.New("down")}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(),
		map[string]Channel{ChannelWebhook: webhook},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := outcome(m, OutcomeGatedUndelivered); got != 1 {
		t.Errorf("outcome gated_undelivered = %v, want 1 (send failed)", got)
	}
	if got := alertResult(m, ChannelWebhook, AlertError); got != 1 {
		t.Errorf("alert webhook/error = %v, want 1", got)
	}
}

func TestHandle_RateLimiterErrorBumpsFailOpenCounter(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	limiter := newFakeLimiter()
	limiter.err = errors.New("redis down")
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		limiter,
		map[string]Channel{ChannelWebhook: webhook},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := testutil.ToFloat64(m.RateLimitFailOpenTotal); got != 1 {
		t.Errorf("ratelimit_failopen = %v, want 1", got)
	}
	// Fail-open still delivers, so the outcome is the normal gated path.
	if got := outcome(m, OutcomeGated); got != 1 {
		t.Errorf("outcome gated = %v, want 1", got)
	}
}

func TestHandle_WithinLimitDoesNotBumpFailOpen(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	webhook := &fakeChannel{name: ChannelWebhook}
	n := New(
		&fakeOrgReader{prefs: prefsWith(70, ChannelWebhook)},
		newFakeLimiter(), // healthy limiter, within-limit allow
		map[string]Channel{ChannelWebhook: webhook},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := testutil.ToFloat64(m.RateLimitFailOpenTotal); got != 0 {
		t.Errorf("ratelimit_failopen = %v, want 0 (normal within-limit allow)", got)
	}
}

func TestHandle_EmailNoRecipientsCountsSkipNotSent(t *testing.T) {
	t.Parallel()
	m := NewMetrics(prometheus.NewRegistry())
	// Real email channel with a stubbed sender; org enables email but has no
	// admin recipients -> Send returns errNoRecipients.
	email := NewEmailChannel(config.SMTPConfig{Host: "h", Port: 25, From: "a@b.c"})
	sentCalled := false
	email.send = func(string, smtp.Auth, string, []string, []byte) error {
		sentCalled = true
		return nil
	}
	prefs := OrgPrefs{
		OrgID: 7, Threshold: 70,
		Channels:    map[string]struct{}{ChannelEmail: {}},
		AdminEmails: nil, // no recipients
	}
	n := New(
		&fakeOrgReader{prefs: prefs},
		newFakeLimiter(),
		map[string]Channel{ChannelEmail: email},
		m,
		zerolog.Nop(),
	)
	if err := n.Handle(context.Background(), msgFor(newVerdict())); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if sentCalled {
		t.Error("relay should not be hit when there are no recipients")
	}
	if got := alertResult(m, ChannelEmail, AlertNoRecipients); got != 1 {
		t.Errorf("alert email/no_recipients = %v, want 1", got)
	}
	if got := alertResult(m, ChannelEmail, AlertSent); got != 0 {
		t.Errorf("alert email/sent = %v, want 0 (no phantom sent)", got)
	}
	if got := outcome(m, OutcomeGatedUndelivered); got != 1 {
		t.Errorf("outcome gated_undelivered = %v, want 1", got)
	}
}
