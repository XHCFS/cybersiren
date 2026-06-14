package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnrich_DNSGate_SkipsWHOISandHTTPForDeadHost asserts the DNS gate: when a
// host does not resolve, the expensive WHOIS and HTTP legs must NOT run. We
// detect "HTTP ran" by pointing the URL at a counting httptest server and
// priming the DNS cache with a negative (empty) result for its host, so DNS
// resolution returns "" without a real lookup.
func TestEnrich_DNSGate_SkipsWHOISandHTTPForDeadHost(t *testing.T) {
	var httpHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&httpHits, 1)
		_, _ = w.Write([]byte("<html><title>x</title></html>"))
	}))
	defer srv.Close()

	host := hostOf(t, srv.URL)

	// Prime the DNS cache with a negative result so the gate sees "does not
	// resolve" without performing a real lookup. (No GeoIP needed: with no IP
	// the enricher returns before any concurrent leg starts.)
	globalDNSCache.set(host, "", dnsCacheTTL)
	t.Cleanup(func() { globalDNSCache.lru.Remove(host) })

	// enricher with a nil geo is fine here because the dead-host path returns
	// before GeoIP is consulted.
	e := &Enricher{}
	eu, err := e.Enrich(context.Background(), srv.URL)
	require.NoError(t, err)
	require.Empty(t, eu.IP, "dead host must have no IP")
	require.Equal(t, int32(0), atomic.LoadInt32(&httpHits), "HTTP leg must be skipped for a dead host")
	require.Zero(t, eu.HTTP.StatusCode, "no HTTP status when host does not resolve")
	require.Empty(t, eu.WHOIS.Registrar, "WHOIS leg must be skipped for a dead host")
}

// TestEnrich_DNSGate_RunsHTTPForLiveHost asserts the complementary case: a host
// that resolves DOES get the HTTP leg. The full Enrich path needs a GeoIP db
// (gated on GEOIP_DIR), so we exercise the post-gate legs directly here to
// confirm a live host's HTTP fetch still runs and parses.
func TestEnrich_DNSGate_RunsHTTPForLiveHost(t *testing.T) {
	allowLoopbackForTest(t)

	var httpHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&httpHits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html lang="en"><head><title>Live</title></head></html>`))
	}))
	defer srv.Close()

	host := hostOf(t, srv.URL)
	require.NotEmpty(t, ResolveIP(context.Background(), host), "loopback host resolves")

	r := FetchHTTP(context.Background(), srv.URL)
	require.Equal(t, 200, r.StatusCode)
	require.Equal(t, "Live", r.Title)
	require.GreaterOrEqual(t, atomic.LoadInt32(&httpHits), int32(1))
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Hostname()
}
