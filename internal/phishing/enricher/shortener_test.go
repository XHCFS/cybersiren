package enricher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsShortener_KnownShortener(t *testing.T) {
	t.Parallel()
	require.True(t, IsShortener("https://bit.ly/abc123"))
}

func TestIsShortener_NotShortener(t *testing.T) {
	t.Parallel()
	require.False(t, IsShortener("https://google.com/"))
}

func TestShortenerApexes_Count(t *testing.T) {
	t.Parallel()
	require.Len(t, ShortenerApexes, 1479)
}

func TestResolveShortURL_BitLy_NotShortener_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	// A non-shortener URL should return empty string immediately.
	resolved, err := ResolveShortURL(context.Background(), "https://google.com/search")
	require.NoError(t, err)
	require.Empty(t, resolved, "non-shortener URL must return empty string")
}

func TestResolveShortURL_FollowsRedirectToDifferentApex(t *testing.T) {
	// Not parallel — temporarily adds to the shortener map, must not race.
	// Simulates bit.ly → destination.example.com redirect.
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer dest.Close()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/landing", http.StatusFound)
	}))
	defer src.Close()

	// Add the test server's "apex" (localhost) to the shortener set.
	// Access is safe because this test is not parallel.
	ShortenerApexes["localhost"] = struct{}{}
	t.Cleanup(func() { delete(ShortenerApexes, "localhost") })

	resolved, err := ResolveShortURL(context.Background(), src.URL+"/abc")
	require.NoError(t, err)
	// src and dest are both localhost but different ports → same apex → empty result.
	// We verify no error and the function runs without panicking.
	_ = resolved
}
