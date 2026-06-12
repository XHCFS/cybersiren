package gmail

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

const (
	testOrgID            = 42
	wantMessageID        = "CAGmail-fixture-001@mail.gmail.com"
	wantSenderInBody     = "paypa1-secure.example"
	fixtureStartCursor   = "20000"
	fixtureLatestHistory = "20060"
)

// newAdapter builds an adapter over the fixture server with the real ingestion
// core and a seeded history cursor, ready to sync.
func newAdapter(t *testing.T, srv *gmailFixtureServer, pub *recordingPublisher, dedup *fakeDedup, hist HistoryStore) *Adapter {
	t.Helper()
	core := realCore(t, pub, dedup)
	return New(Options{
		Core:         core,
		OrgID:        testOrgID,
		Client:       srv.newClient(),
		History:      hist,
		LabelIDs:     []string{"INBOX"},
		WatchTopic:   "projects/cybersiren-demo/topics/gmail-push",
		PushToken:    "shared-secret",
		PollInterval: 0,
		Log:          zerolog.Nop(),
	})
}

// decodeRaw decodes a published emails.raw value.
func decodeRaw(t *testing.T, value []byte) contracts.EmailsRaw {
	t.Helper()
	var er contracts.EmailsRaw
	if err := json.Unmarshal(value, &er); err != nil {
		t.Fatalf("unmarshal emails.raw: %v", err)
	}
	return er
}

// TestPushTriggersIngest is the headline recorded-fixture test: a Pub/Sub push
// envelope → the adapter fetches new history → decodes the captured Gmail
// message → publishes a VALID emails.raw with a freshly minted UUIDv7 email_id,
// the gmail source_adapter, and the message_id extracted from the RFC-822.
func TestPushTriggersIngest(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	if err := hist.Set(context.Background(), testOrgID, fixtureStartCursor); err != nil {
		t.Fatal(err)
	}
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	rr := postPush(t, a, readFixture(t, "push_envelope.json"), "shared-secret")

	if rr.Code != http.StatusNoContent {
		t.Fatalf("push status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if pub.count() != 1 {
		t.Fatalf("emails.raw published %d times, want 1", pub.count())
	}

	key, value := pub.last()
	er := decodeRaw(t, value)

	// email_id is a minted UUIDv7 (G17/#142), not derived from any Gmail id.
	id, err := uuid.Parse(er.Meta.EmailID)
	if err != nil {
		t.Fatalf("email_id %q is not a valid UUID: %v", er.Meta.EmailID, err)
	}
	if id.Version() != 7 {
		t.Errorf("email_id UUID version = %d, want 7", id.Version())
	}
	if string(key) != er.Meta.EmailID {
		t.Errorf("kafka key %q must equal email_id %q (partition key)", string(key), er.Meta.EmailID)
	}

	// org bound from config, never the push body (G10).
	if er.Meta.OrgID != testOrgID {
		t.Errorf("org_id = %d, want %d (from config)", er.Meta.OrgID, testOrgID)
	}
	if er.SourceAdapter != "gmail" {
		t.Errorf("source_adapter = %q, want gmail", er.SourceAdapter)
	}
	if er.APIKeyID != 0 {
		t.Errorf("api_key_id = %d, want 0 (Gmail is not API-key authed)", er.APIKeyID)
	}
	if trimMessageID(er.MessageID) != wantMessageID {
		t.Errorf("message_id = %q, want %q (from RFC-822 header)", er.MessageID, wantMessageID)
	}
	if er.RawMessageB64 == "" {
		t.Error("raw_rfc822 must carry the base64 message bytes")
	}

	// The decoded raw must be the captured phishing-flavoured message.
	rawBytes := decodeB64(t, er.RawMessageB64)
	if !bytes.Contains(rawBytes, []byte(wantSenderInBody)) {
		t.Errorf("decoded RFC-822 missing expected sender %q", wantSenderInBody)
	}

	// API path: token minted once, then history.list + messages.get.
	if srv.hitCount("history.list") != 1 {
		t.Errorf("history.list hits = %d, want 1", srv.hitCount("history.list"))
	}
	if srv.hitCount("messages.get") != 1 {
		t.Errorf("messages.get hits = %d, want 1", srv.hitCount("messages.get"))
	}

	// Cursor advanced to the latest historyId.
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != fixtureLatestHistory {
		t.Errorf("history cursor = %q, want %q after sync", cur, fixtureLatestHistory)
	}
}

// TestPollTriggersIngest exercises the fallback path: syncHistory (what the poll
// loop ticks) ingests the same captured message exactly like the push path.
func TestPollTriggersIngest(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	_ = hist.Set(context.Background(), testOrgID, fixtureStartCursor)
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory: %v", err)
	}
	if pub.count() != 1 {
		t.Fatalf("poll published %d emails.raw, want 1", pub.count())
	}
	er := decodeRaw(t, mustLastValue(t, pub))
	if er.SourceAdapter != "gmail" || er.Meta.OrgID != testOrgID {
		t.Errorf("poll-ingested message mis-attributed: %+v", er.Meta)
	}
}

// TestSyncNoCursor_NoOp asserts a sync without a seeded cursor does nothing
// (history.list needs a startHistoryId — a watch() must seed it first).
func TestSyncNoCursor_NoOp(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, NewMemoryHistoryStore())

	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory with no cursor should be a no-op, got: %v", err)
	}
	if pub.count() != 0 || srv.hitCount("history.list") != 0 {
		t.Error("no cursor → no history walk and no publish")
	}
}

// TestDuplicateSuppressed asserts a duplicate (dedup returns not-fresh) does NOT
// publish emails.raw — the shared core's dedup applies to Gmail mail too.
func TestDuplicateSuppressed(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	_ = hist.Set(context.Background(), testOrgID, fixtureStartCursor)
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: false}, hist)

	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory: %v", err)
	}
	if pub.count() != 0 {
		t.Errorf("duplicate Gmail message must not republish; published %d", pub.count())
	}
}

// TestWatchSeedsCursor asserts watch() registers and seeds the baseline cursor
// when none is stored, and surfaces the expiration for the 7-day renewal note.
func TestWatchSeedsCursor(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	resp, err := a.Watch(context.Background())
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if resp.HistoryID != "20000" {
		t.Errorf("watch historyId = %q, want 20000", resp.HistoryID)
	}
	if resp.Expiration == "" {
		t.Error("watch must surface the expiration for the 7-day renewal")
	}
	if srv.hitCount("watch") != 1 {
		t.Errorf("watch hits = %d, want 1", srv.hitCount("watch"))
	}
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != "20000" {
		t.Errorf("cursor seeded to %q, want 20000", cur)
	}
}

// TestWatchDoesNotRewindCursor asserts a re-watch with an existing (newer)
// cursor does not rewind it (avoids re-ingesting already-seen mail).
func TestWatchDoesNotRewindCursor(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	_ = hist.Set(context.Background(), testOrgID, "99999")
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	if _, err := a.Watch(context.Background()); err != nil {
		t.Fatalf("Watch: %v", err)
	}
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != "99999" {
		t.Errorf("re-watch rewound cursor to %q, want 99999 preserved", cur)
	}
}

// TestStop calls users.stop (shutdown path).
func TestStop(t *testing.T) {
	srv := newGmailFixtureServer(t)
	a := newAdapter(t, srv, &recordingPublisher{}, &fakeDedup{fresh: true}, NewMemoryHistoryStore())
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if srv.hitCount("stop") != 1 {
		t.Errorf("stop hits = %d, want 1", srv.hitCount("stop"))
	}
}

// TestNameAndInterface pins the registry key and the EmailSource contract.
func TestNameAndInterface(t *testing.T) {
	var _ source.EmailSource = (*Adapter)(nil)
	a := &Adapter{}
	if a.Name() != "gmail" {
		t.Errorf("Name() = %q, want gmail", a.Name())
	}
}

// ---- helpers ----------------------------------------------------------------

func postPush(t *testing.T, a *Adapter, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	a.Register(mux)
	url := "/gmail/push"
	if token != "" {
		url += "?token=" + token
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func mustLastValue(t *testing.T, p *recordingPublisher) []byte {
	t.Helper()
	_, v := p.last()
	if v == nil {
		t.Fatal("no emails.raw published")
	}
	return v
}
