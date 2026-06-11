package vt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const sampleReport = `{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 7,
        "suspicious": 1,
        "harmless": 60,
        "undetected": 5,
        "timeout": 0
      }
    }
  }
}`

func TestLookup_NoKeySkips(t *testing.T) {
	c := New("", DefaultBaseURL, time.Second)
	if c.Enabled() {
		t.Fatal("client with empty key must report Enabled()==false")
	}
	res, err := c.Lookup(context.Background(), "abc")
	if err != nil {
		t.Fatalf("no-key lookup must never error, got %v", err)
	}
	if !res.Skipped {
		t.Fatal("no-key lookup must be Skipped")
	}
	// F7: no-key is a config skip, never a confirmed miss.
	if res.NotFound {
		t.Fatal("no-key lookup must NOT set NotFound")
	}
}

func TestLookup_429FailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New("k", srv.URL, time.Second)
	res, err := c.Lookup(context.Background(), "deadbeef")
	if err != nil {
		t.Fatalf("429 must fail open with nil error, got %v", err)
	}
	if !res.Skipped {
		t.Fatal("429 must yield a Skipped result")
	}
	if res.Malicious() {
		t.Fatal("429 must not report malicious")
	}
	// F7: a 429 is transient, NOT a confirmed miss — it must not set NotFound, so
	// the caller does not negatively cache it.
	if res.NotFound {
		t.Fatal("429 must NOT set NotFound (it is transient, not a confirmed miss)")
	}
}

func TestLookup_404Miss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New("k", srv.URL, time.Second)
	res, err := c.Lookup(context.Background(), "unknownhash")
	if err != nil {
		t.Fatalf("404 must be a clean miss, got %v", err)
	}
	if !res.Skipped {
		t.Fatal("404 must yield a Skipped result")
	}
	// F7: a 404 is a CONFIRMED miss (the hash is genuinely unknown to VT), so
	// NotFound must be set to let the caller negatively cache it.
	if !res.NotFound {
		t.Fatal("404 must set NotFound so the caller can negatively cache the miss")
	}
}

func TestLookup_AuthRejectedErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := New("badkey", srv.URL, time.Second)
	res, err := c.Lookup(context.Background(), "h")
	if err == nil {
		t.Fatal("401 should surface an error")
	}
	if !res.Skipped {
		t.Fatal("401 should still yield a Skipped result so the caller fails open")
	}
	// F7: an auth rejection is a config fault, not a confirmed miss.
	if res.NotFound {
		t.Fatal("401 must NOT set NotFound")
	}
}

func TestLookup_OKParsesStats(t *testing.T) {
	var gotKey, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-apikey")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleReport))
	}))
	defer srv.Close()

	c := New("secret", srv.URL, time.Second)
	res, err := c.Lookup(context.Background(), "AABBCC")
	if err != nil {
		t.Fatalf("ok lookup errored: %v", err)
	}
	if res.Skipped {
		t.Fatal("a 200 with stats must not be Skipped")
	}
	if !res.Malicious() {
		t.Fatalf("malicious_votes=%d should report malicious", res.MaliciousVotes)
	}
	if res.MaliciousVotes != 7 || res.SuspiciousVotes != 1 || res.HarmlessVotes != 60 {
		t.Fatalf("parsed votes wrong: %+v", res)
	}
	if len(res.Raw) == 0 {
		t.Fatal("raw body should be retained for the cache")
	}
	if gotKey != "secret" {
		t.Fatalf("x-apikey header = %q, want secret", gotKey)
	}
	// Hash must be lowercased into the path.
	if want := "/files/aabbcc"; gotPath != want {
		t.Fatalf("request path = %q, want %q", gotPath, want)
	}
}

func TestLookup_MalformedBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := New("k", srv.URL, time.Second)
	res, err := c.Lookup(context.Background(), "h")
	if err == nil {
		t.Fatal("malformed body should error")
	}
	if !res.Skipped {
		t.Fatal("malformed body should yield a Skipped result (fail open)")
	}
}
