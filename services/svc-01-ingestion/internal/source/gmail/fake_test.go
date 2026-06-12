package gmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/ingest"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
)

// ---- shared test doubles ----------------------------------------------------

// allowDedup treats every message as fresh (publish). passDedup=false simulates
// a duplicate.
type fakeDedup struct {
	fresh bool
	calls int
}

func (f *fakeDedup) Claim(_ context.Context, _ int64, _ string) (bool, error) {
	f.calls++
	return f.fresh, nil
}

// unlimitedQuota always allows.
type fakeQuota struct{}

func (fakeQuota) Allow(_ context.Context, _ int64, _ *int32) (bool, error) { return true, nil }

// nilOrg reports an unlimited monthly limit.
type nilOrg struct{}

func (nilOrg) MonthlyLimit(_ context.Context, _ int64) (*int32, error) { return nil, nil }

// recordingPublisher captures every published emails.raw message.
type recordingPublisher struct {
	mu     sync.Mutex
	keys   [][]byte
	values [][]byte
}

func (p *recordingPublisher) Publish(_ context.Context, key, value []byte, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = append(p.keys, key)
	p.values = append(p.values, value)
	return nil
}

func (p *recordingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.values)
}

func (p *recordingPublisher) last() (key, value []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.values)
	if n == 0 {
		return nil, nil
	}
	return p.keys[n-1], p.values[n-1]
}

// realCore builds the production ingestion Core with test doubles so the Gmail
// adapter exercises the genuine auth/dedup/quota/UUIDv7/publish path.
func realCore(t *testing.T, pub ingest.Publisher, dedup ingest.Deduper) source.Ingestor {
	t.Helper()
	return ingest.NewCore(ingest.Config{
		Dedup:    dedup,
		Quota:    fakeQuota{},
		Orgs:     nilOrg{},
		Producer: pub,
		Log:      zerolog.Nop(),
	})
}

// readFixture loads a testdata file or fails the test.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// gmailFixtureServer is an httptest server that replays the recorded Gmail
// fixtures: the OAuth token endpoint, history.list, messages.get, watch, stop.
// It records which paths were hit so tests can assert the adapter called the
// expected API. requireBearer, when set, asserts every API call carried the
// minted access token.
type gmailFixtureServer struct {
	srv          *httptest.Server
	t            *testing.T
	requireToken string

	mu        sync.Mutex
	hits      map[string]int
	stopCalls int
}

func newGmailFixtureServer(t *testing.T) *gmailFixtureServer {
	t.Helper()
	g := &gmailFixtureServer{t: t, hits: map[string]int{}, requireToken: "ya29.fixture-access-token"}
	mux := http.NewServeMux()

	// OAuth2 token endpoint.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		g.record("token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "token.json"))
	})

	// Gmail API. ServeMux longest-prefix routing distinguishes history/watch/stop
	// from the per-message get.
	mux.HandleFunc("/gmail/v1/users/me/history", func(w http.ResponseWriter, r *http.Request) {
		g.assertBearer(r)
		g.record("history.list")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "history_list.json"))
	})
	mux.HandleFunc("/gmail/v1/users/me/watch", func(w http.ResponseWriter, r *http.Request) {
		g.assertBearer(r)
		g.record("watch")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "watch.json"))
	})
	mux.HandleFunc("/gmail/v1/users/me/stop", func(w http.ResponseWriter, r *http.Request) {
		g.assertBearer(r)
		g.mu.Lock()
		g.stopCalls++
		g.mu.Unlock()
		g.record("stop")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/gmail/v1/users/me/messages/", func(w http.ResponseWriter, r *http.Request) {
		g.assertBearer(r)
		g.record("messages.get")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(readFixture(t, "message_raw.json"))
	})

	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gmailFixtureServer) record(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hits[name]++
}

func (g *gmailFixtureServer) hitCount(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[name]
}

func (g *gmailFixtureServer) assertBearer(r *http.Request) {
	if g.requireToken == "" {
		return
	}
	want := "Bearer " + g.requireToken
	if got := r.Header.Get("Authorization"); got != want {
		g.t.Errorf("Gmail API call %s missing/wrong bearer: got %q, want %q", r.URL.Path, got, want)
	}
}

// newClient builds a Gmail client pointed at the fixture server.
func (g *gmailFixtureServer) newClient() *client {
	tokens := newTokenSource("client-id", "client-secret", "refresh-tok", g.srv.URL+"/token", g.srv.Client())
	return newClient(g.srv.URL, "me", tokens, g.srv.Client())
}

// trimMessageID is a tiny helper kept here so message-id assertions read
// cleanly across test files.
func trimMessageID(s string) string { return strings.Trim(s, "<>") }

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
