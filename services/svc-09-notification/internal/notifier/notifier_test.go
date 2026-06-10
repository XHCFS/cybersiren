package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/rs/zerolog"

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
