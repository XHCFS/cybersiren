package phishing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// withFakeClock swaps nowFunc for a controllable clock and restores it.
func withFakeClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Now()
	nowFunc = func() time.Time { return now }
	t.Cleanup(func() { nowFunc = time.Now })
	return &now
}

func TestCircuitBreaker_TripsAfterThreshold(t *testing.T) {
	clk := withFakeClock(t)
	b := newCircuitBreaker()

	require.True(t, b.Allow(), "starts closed")
	require.Equal(t, breakerClosed, b.State())

	// One short of the threshold: still closed and allowing.
	for i := 0; i < breakerFailureThreshold-1; i++ {
		b.Failure()
	}
	require.Equal(t, breakerClosed, b.State())
	require.True(t, b.Allow())

	// The threshold-th failure trips it OPEN.
	b.Failure()
	require.Equal(t, breakerOpen, b.State())
	require.False(t, b.Allow(), "OPEN breaker blocks enrichment")

	// Before cooldown elapses it stays OPEN.
	*clk = clk.Add(breakerCooldown - time.Millisecond)
	require.False(t, b.Allow())

	// After cooldown it half-opens and allows exactly one probe.
	*clk = clk.Add(2 * time.Millisecond)
	require.True(t, b.Allow(), "first call after cooldown probes (half-open)")
	require.Equal(t, breakerHalfOpen, b.State())
	require.False(t, b.Allow(), "second concurrent call is held until probe reports")
}

func TestCircuitBreaker_HalfOpenSuccessCloses(t *testing.T) {
	clk := withFakeClock(t)
	b := newCircuitBreaker()
	for i := 0; i < breakerFailureThreshold; i++ {
		b.Failure()
	}
	require.Equal(t, breakerOpen, b.State())

	*clk = clk.Add(breakerCooldown)
	require.True(t, b.Allow()) // half-open probe
	b.Success()
	require.Equal(t, breakerClosed, b.State(), "successful probe closes the breaker")
	require.True(t, b.Allow())
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	clk := withFakeClock(t)
	b := newCircuitBreaker()
	for i := 0; i < breakerFailureThreshold; i++ {
		b.Failure()
	}
	*clk = clk.Add(breakerCooldown)
	require.True(t, b.Allow()) // half-open probe
	b.Failure()
	require.Equal(t, breakerOpen, b.State(), "failed probe re-opens the breaker")
	require.False(t, b.Allow())
}

func TestCircuitBreaker_OldFailuresAgeOutOfWindow(t *testing.T) {
	clk := withFakeClock(t)
	b := newCircuitBreaker()

	// Record threshold-1 failures, then advance past the window so they age out.
	for i := 0; i < breakerFailureThreshold-1; i++ {
		b.Failure()
	}
	*clk = clk.Add(breakerWindow + time.Second)

	// A fresh burst short of the threshold must NOT trip, because the earlier
	// failures fell out of the rolling window.
	for i := 0; i < breakerFailureThreshold-1; i++ {
		b.Failure()
	}
	require.Equal(t, breakerClosed, b.State(), "aged-out failures don't count toward the threshold")
}
