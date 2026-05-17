package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func sidecarStub(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient_Score_ParsesResponse(t *testing.T) {
	t.Parallel()

	srv := sidecarStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/score", r.URL.Path)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &payload))
		urls, ok := payload["urls"].([]interface{})
		require.True(t, ok)
		require.Len(t, urls, 1)
		require.Equal(t, "https://example.com/", urls[0])

		resp := map[string]interface{}{
			"results": []map[string]interface{}{
				{
					"url":          "https://example.com/",
					"effective_url": "https://example.com/",
					"url_p":        0.01,
					"op_p":         0.02,
					"deploy_p":     0.015,
					"verdict":      "benign",
				},
			},
			"threshold":   0.5,
			"fusion_mode": "mean",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	result, err := c.Score(context.Background(), ScoreRequest{URL: "https://example.com/"})
	require.NoError(t, err)
	require.Equal(t, "benign", result.Verdict)
	require.InDelta(t, 0.015, result.DeployP, 0.001)
	require.Equal(t, "https://example.com/", result.EffectiveURL)
}

func TestClient_CachedScore_CacheHitSkipsHTTP(t *testing.T) {
	t.Parallel()

	calls := 0
	srv := sidecarStub(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := map[string]interface{}{
			"results": []map[string]interface{}{
				{
					"url":          "https://example.com/",
					"effective_url": "https://example.com/",
					"url_p":        0.1,
					"op_p":         0.2,
					"deploy_p":     0.15,
					"verdict":      "benign",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	// First call — cache miss.
	_, hit1, err := c.CachedScore(context.Background(), "https://example.com/", "example.com")
	require.NoError(t, err)
	require.False(t, hit1)
	require.Equal(t, 1, calls)

	// Second call — cache hit, no HTTP request.
	_, hit2, err := c.CachedScore(context.Background(), "https://example.com/", "example.com")
	require.NoError(t, err)
	require.True(t, hit2)
	require.Equal(t, 1, calls, "sidecar should not be called again")
}
