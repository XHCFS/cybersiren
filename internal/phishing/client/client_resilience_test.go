package client

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// oneBenignResult writes a minimal valid /score response.
func oneBenignResult(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"results": []map[string]interface{}{
			{"url": "https://e.com/", "effective_url": "https://e.com/", "verdict": "benign", "deploy_p": 0.1},
		},
	})
}

func TestClient_RetriesTransient5xxThenSucceeds(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := sidecarStub(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient
			return
		}
		oneBenignResult(w)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	res, err := c.Score(context.Background(), ScoreRequest{URL: "https://e.com/"})
	require.NoError(t, err, "a single transient 5xx must be retried, not surfaced")
	require.Equal(t, "benign", res.Verdict)
	require.Equal(t, int32(2), calls.Load(), "exactly one retry after a transient 5xx")
}

func TestClient_GivesUpAfterMaxRetriesOn5xx(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := sidecarStub(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	_, err = c.Score(context.Background(), ScoreRequest{URL: "https://e.com/"})
	require.Error(t, err)
	require.Equal(t, int32(sidecarMaxRetries+1), calls.Load(), "bounded: initial attempt + maxRetries")
}

func TestClient_NoRetryOn4xx(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := sidecarStub(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest) // client error: not transient
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	_, err = c.Score(context.Background(), ScoreRequest{URL: "https://e.com/"})
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load(), "a 4xx is terminal and must not be retried")
}

func TestClient_NoRetryWhenContextAlreadyExpired(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := sidecarStub(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	// A short deadline that elapses during the first attempt leaves no budget,
	// so the transient 5xx must NOT be retried (a retry would fail the same way).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = c.Score(ctx, ScoreRequest{URL: "https://e.com/"})
	require.Error(t, err)
	require.LessOrEqual(t, calls.Load(), int32(1), "no retry once the context budget is gone")
}

// TestClient_ConcurrencyCapped verifies the semaphore bounds in-flight sidecar
// calls so a burst cannot stampede the single sidecar.
func TestClient_ConcurrencyCapped(t *testing.T) {
	t.Parallel()
	var inflight, maxSeen atomic.Int32
	srv := sidecarStub(t, func(w http.ResponseWriter, _ *http.Request) {
		cur := inflight.Add(1)
		for {
			m := maxSeen.Load()
			if cur <= m || maxSeen.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond) // hold the slot so concurrency builds up
		inflight.Add(-1)
		oneBenignResult(w)
	})

	c, err := NewClient(srv.URL)
	require.NoError(t, err)

	const launched = sidecarMaxConcurrency * 3
	var wg sync.WaitGroup
	for i := 0; i < launched; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct URLs so every call misses the cache and hits the sidecar.
			url := "https://e.com/" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			_, _, _ = c.CachedScore(context.Background(), url, "e.com")
		}(i)
	}
	wg.Wait()

	require.LessOrEqual(t, maxSeen.Load(), int32(sidecarMaxConcurrency),
		"in-flight sidecar calls must never exceed the concurrency cap")
	require.Greater(t, maxSeen.Load(), int32(1), "the test should actually exercise concurrency")
}
