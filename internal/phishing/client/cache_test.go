package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache_SetAndGet(t *testing.T) {
	t.Parallel()
	c, err := NewCache(100, time.Minute)
	require.NoError(t, err)

	c.Set("example.com", ScoreResult{Verdict: "benign", DeployP: 0.01})
	r, ok := c.Get("example.com")
	require.True(t, ok)
	require.Equal(t, "benign", r.Verdict)
}

func TestCache_TTLExpiry(t *testing.T) {
	t.Parallel()
	c, err := NewCache(100, 1*time.Millisecond)
	require.NoError(t, err)

	c.Set("example.com", ScoreResult{Verdict: "phishing"})
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("example.com")
	require.False(t, ok, "entry should have expired")
}

func TestCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	c, err := NewCache(1000, time.Minute)
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			key := "domain" + string(rune('a'+n%26))
			c.Set(key, ScoreResult{Verdict: "benign"})
		}(i)
		go func(n int) {
			defer wg.Done()
			key := "domain" + string(rune('a'+n%26))
			c.Get(key)
		}(i)
	}
	wg.Wait()
}
