package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnricher_WithSyntheticServer(t *testing.T) {
	dir := os.Getenv("GEOIP_DIR")
	if dir == "" {
		t.Skip("GEOIP_DIR not set")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html lang="en"><head><title>Test Page</title></head><body></body></html>`))
	}))
	defer srv.Close()

	e, err := New(dir)
	require.NoError(t, err)
	defer e.Close()

	eu, err := e.Enrich(context.Background(), srv.URL)
	require.NoError(t, err)
	require.Equal(t, "Test Page", eu.HTTP.Title)
	require.Equal(t, "en", eu.HTTP.Language)
	require.Equal(t, 200, eu.HTTP.StatusCode)
}
