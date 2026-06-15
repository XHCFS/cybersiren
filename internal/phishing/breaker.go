package phishing

import (
	"sync"
	"time"
)

// Circuit-breaker tuning. These bound how the detector reacts to a degraded
// network window where the L2 enricher's per-leg timeouts would otherwise be
// paid on every single URL.
const (
	// breakerWindow is the rolling window over which enrichment failures are
	// counted.
	breakerWindow = 30 * time.Second
	// breakerFailureThreshold is the number of enrichment failures within
	// breakerWindow that trips the breaker OPEN.
	breakerFailureThreshold = 5
	// breakerCooldown is how long the breaker stays OPEN (enrichment skipped,
	// fail-open) before allowing a single half-open probe.
	breakerCooldown = 15 * time.Second
)

// breakerState enumerates the circuit-breaker states.
type breakerState int

const (
	breakerClosed   breakerState = iota // healthy: enrichment allowed
	breakerOpen                         // tripped: enrichment skipped (fail-open)
	breakerHalfOpen                     // probing: one request allowed through
)

// nowFunc is overridable in tests so the time-based transitions can be driven
// deterministically without sleeping.
var nowFunc = time.Now

// circuitBreaker is a lightweight failure-rate breaker around the L2 network
// enricher. It is safe for concurrent use (the per-email loop scans URLs in
// parallel). When OPEN it short-circuits enrichment so each URL fails open
// immediately instead of independently eating the per-leg timeouts during a
// degraded-network window.
type circuitBreaker struct {
	mu sync.Mutex

	state    breakerState
	failures []time.Time // failure timestamps within the rolling window
	openedAt time.Time   // when the breaker last tripped OPEN
}

func newCircuitBreaker() *circuitBreaker {
	return &circuitBreaker{state: breakerClosed}
}

// Allow reports whether an enrichment attempt may proceed. When the breaker is
// OPEN and the cooldown has elapsed it transitions to HALF-OPEN and lets a
// single probe through; the caller MUST report the probe's outcome via
// Success/Failure so the breaker can close or re-open.
func (b *circuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case breakerOpen:
		if nowFunc().Sub(b.openedAt) >= breakerCooldown {
			// Cooldown elapsed: allow one probe.
			b.state = breakerHalfOpen
			return true
		}
		return false
	case breakerHalfOpen:
		// A probe is already in flight; hold others until it reports back.
		return false
	default: // breakerClosed
		return true
	}
}

// Success records a successful enrichment. From HALF-OPEN it closes the breaker
// and clears the failure window.
func (b *circuitBreaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == breakerHalfOpen {
		b.state = breakerClosed
		b.failures = nil
	}
}

// Failure records a failed/timed-out enrichment. A failure during the HALF-OPEN
// probe re-opens the breaker immediately. Otherwise the failure is appended to
// the rolling window and the breaker trips OPEN once the threshold is exceeded.
func (b *circuitBreaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := nowFunc()
	if b.state == breakerHalfOpen {
		b.trip(now)
		return
	}

	// Drop failures outside the window, then record this one.
	cutoff := now.Add(-breakerWindow)
	kept := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.failures = append(kept, now)

	if len(b.failures) >= breakerFailureThreshold {
		b.trip(now)
	}
}

// trip moves the breaker to OPEN. Caller must hold b.mu.
func (b *circuitBreaker) trip(now time.Time) {
	b.state = breakerOpen
	b.openedAt = now
	b.failures = nil
}

// State returns the current breaker state (for tests / observability).
func (b *circuitBreaker) State() breakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
