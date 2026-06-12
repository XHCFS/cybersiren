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

// TestSyncNoCursor_SelfSeeds asserts a sync without a seeded cursor self-heals
// by seeding from the mailbox profile (poll-only deployments have no watch() to
// seed it), then returns without walking history or publishing — the next tick
// delta-syncs from the freshly seeded baseline. This is the poll-only fix:
// previously a missing cursor meant "ingest nothing forever".
func TestSyncNoCursor_SelfSeeds(t *testing.T) {
	srv := newGmailFixtureServer(t)
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory with no cursor should self-seed, got: %v", err)
	}
	// No mail ingested this tick (we seed to "now"), and no history walked.
	if pub.count() != 0 || srv.hitCount("history.list") != 0 {
		t.Error("first sync with no cursor → seed only; no history walk, no publish")
	}
	// The cursor is now seeded from getProfile (profile.json historyId=30000).
	if srv.hitCount("profile") != 1 {
		t.Errorf("getProfile hits = %d, want 1 (seeding)", srv.hitCount("profile"))
	}
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != "30000" {
		t.Errorf("cursor seeded to %q, want 30000 from getProfile", cur)
	}
}

// TestEnsureSeeded_PollOnlySeedsFromProfile asserts the poll-only fix:
// EnsureSeeded fetches the mailbox baseline via getProfile and stores it when no
// cursor exists, and is a no-op (no getProfile, no rewind) when one already does.
func TestEnsureSeeded_PollOnlySeedsFromProfile(t *testing.T) {
	srv := newGmailFixtureServer(t)
	hist := NewMemoryHistoryStore()
	a := newAdapter(t, srv, &recordingPublisher{}, &fakeDedup{fresh: true}, hist)

	// No cursor → seed from getProfile (profile.json historyId=30000).
	if err := a.EnsureSeeded(context.Background()); err != nil {
		t.Fatalf("EnsureSeeded (unseeded): %v", err)
	}
	if srv.hitCount("profile") != 1 {
		t.Errorf("getProfile hits = %d, want 1", srv.hitCount("profile"))
	}
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != "30000" {
		t.Fatalf("seeded cursor = %q, want 30000", cur)
	}

	// Already seeded → no-op: no further getProfile call, cursor unchanged.
	if err := a.EnsureSeeded(context.Background()); err != nil {
		t.Fatalf("EnsureSeeded (already seeded): %v", err)
	}
	if srv.hitCount("profile") != 1 {
		t.Errorf("getProfile hits = %d after second call, want still 1 (no-op when seeded)", srv.hitCount("profile"))
	}
	cur, _ = hist.Get(context.Background(), testOrgID)
	if cur != "30000" {
		t.Errorf("cursor changed to %q on no-op EnsureSeeded, want 30000 preserved", cur)
	}
}

// TestSyncHistory_CursorHeldOnMessageFailure asserts that when processMessage
// fails (here: messages.get 500s), the cursor is NOT advanced past the window,
// so the failed message is re-listed next tick instead of being silently
// dropped. Advancing the cursor on failure was the silent-drop bug.
func TestSyncHistory_CursorHeldOnMessageFailure(t *testing.T) {
	srv := newGmailFixtureServer(t)
	srv.messageStatus = http.StatusInternalServerError // make processMessage fail
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	if err := hist.Set(context.Background(), testOrgID, fixtureStartCursor); err != nil {
		t.Fatal(err)
	}
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	// syncHistory must NOT return an error (it logs+continues per message)...
	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory: %v", err)
	}
	// ...nothing published (the fetch failed)...
	if pub.count() != 0 {
		t.Errorf("published %d emails.raw, want 0 on message-fetch failure", pub.count())
	}
	// ...and crucially the cursor is HELD at the start value, not advanced to
	// fixtureLatestHistory — so the window re-walks next tick.
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != fixtureStartCursor {
		t.Errorf("cursor = %q after a failed message, want it HELD at %q (not advanced — that is the silent-drop bug)", cur, fixtureStartCursor)
	}

	// Sanity: once the message succeeds, the cursor advances normally.
	srv.messageStatus = 0
	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory (recovered): %v", err)
	}
	if pub.count() != 1 {
		t.Errorf("published %d after recovery, want 1", pub.count())
	}
	cur, _ = hist.Get(context.Background(), testOrgID)
	if cur != fixtureLatestHistory {
		t.Errorf("cursor = %q after recovery, want %q advanced", cur, fixtureLatestHistory)
	}
}

// TestSyncHistory_HistoryTooOldReseeds asserts that a 404 from history.list
// (startHistoryId aged out of Gmail's history retention) re-seeds the cursor to
// the current getProfile historyId and returns nil (recovered), instead of
// returning the error and leaving the cursor stuck forever (silent halt).
func TestSyncHistory_HistoryTooOldReseeds(t *testing.T) {
	srv := newGmailFixtureServer(t)
	srv.historyStatus = http.StatusNotFound // history.list → 404 "too old"
	srv.profileHistoryID = "45000"          // re-seed target
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	if err := hist.Set(context.Background(), testOrgID, "100"); err != nil { // stale cursor
		t.Fatal(err)
	}
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	// 404 must be RECOVERED, not surfaced as an error.
	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory on history-too-old should recover (nil), got: %v", err)
	}
	// Re-seeded to the fresh profile historyId; the stale cursor is un-stuck.
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != "45000" {
		t.Errorf("cursor = %q after 404, want re-seeded to 45000 (getProfile)", cur)
	}
	if srv.hitCount("profile") != 1 {
		t.Errorf("getProfile hits = %d, want 1 (re-seed)", srv.hitCount("profile"))
	}
	if pub.count() != 0 {
		t.Errorf("published %d during re-seed, want 0 (gap mail is unavoidably missed)", pub.count())
	}

	// After re-seed, history.list recovers and a normal sync delta-syncs again.
	srv.historyStatus = 0
	// Move the stored cursor to the fixture start so the recorded page applies.
	if err := hist.Set(context.Background(), testOrgID, fixtureStartCursor); err != nil {
		t.Fatal(err)
	}
	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory after recovery: %v", err)
	}
	if pub.count() != 1 {
		t.Errorf("published %d after recovery, want 1", pub.count())
	}
}

// TestSyncHistory_DeletedMessageSkippedNotHeld asserts a messages.get 404 (the
// message was deleted between history.list and the fetch — a routine Gmail race)
// is SKIPPED: the cursor ADVANCES past the vanished id rather than being held
// forever, which would starve all later mail behind one un-fetchable message.
// Contrast TestSyncHistory_CursorHeldOnMessageFailure, where a 500 is a real
// failure that correctly holds the cursor.
func TestSyncHistory_DeletedMessageSkippedNotHeld(t *testing.T) {
	srv := newGmailFixtureServer(t)
	srv.messageStatus = http.StatusNotFound // message deleted before fetch
	pub := &recordingPublisher{}
	hist := NewMemoryHistoryStore()
	if err := hist.Set(context.Background(), testOrgID, fixtureStartCursor); err != nil {
		t.Fatal(err)
	}
	a := newAdapter(t, srv, pub, &fakeDedup{fresh: true}, hist)

	if err := a.syncHistory(context.Background()); err != nil {
		t.Fatalf("syncHistory: %v", err)
	}
	// Nothing published — the message is gone.
	if pub.count() != 0 {
		t.Errorf("published %d emails.raw, want 0 for a 404'd message", pub.count())
	}
	// Crucially the cursor ADVANCES past the deleted id (404 skipped, not held),
	// so the window does not re-walk forever.
	cur, _ := hist.Get(context.Background(), testOrgID)
	if cur != fixtureLatestHistory {
		t.Errorf("cursor = %q after a 404'd message, want it ADVANCED to %q (deleted message skipped, not a permanent halt)", cur, fixtureLatestHistory)
	}
}

// TestTick_RecoversPanic asserts a panic inside a background-loop tick is
// recovered, not propagated — the loops run as bare goroutines off main, so an
// unrecovered panic would crash the whole svc-01 process (API path included).
func TestTick_RecoversPanic(t *testing.T) {
	a := &Adapter{log: zerolog.Nop()}
	a.tick("test", func() error { panic("boom") }) // must NOT propagate
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
