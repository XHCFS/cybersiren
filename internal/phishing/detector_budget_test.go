package phishing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestL2EnrichCtx verifies the L2 budget split: enrichment is capped so the
// parent context retains a slice for the sidecar inference call, which was the
// fix for "phishing ML check failed: context deadline exceeded" under load.
func TestL2EnrichCtx(t *testing.T) {
	t.Parallel()

	t.Run("reserves the tail of a deadline budget for the sidecar", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()

		ec, c := l2EnrichCtx(parent, 700*time.Millisecond)
		defer c()

		dl, ok := ec.Deadline()
		require.True(t, ok, "enrich context must carry a deadline")
		enrichBudget := time.Until(dl)
		// 2500ms parent - 700ms reserve ≈ 1800ms enrichment budget.
		require.InDelta(t, float64(1800*time.Millisecond), float64(enrichBudget), float64(200*time.Millisecond))

		// The parent must keep clearly more than the enrich budget — i.e. ~reserve
		// is left for the sidecar call that runs on the parent ctx afterwards.
		pdl, _ := parent.Deadline()
		require.Greater(t, float64(time.Until(pdl)-enrichBudget), float64(500*time.Millisecond),
			"parent must retain a usable slice for the sidecar call")
	})

	t.Run("no parent deadline returns ctx unchanged", func(t *testing.T) {
		t.Parallel()
		ec, c := l2EnrichCtx(context.Background(), 700*time.Millisecond)
		defer c()
		_, ok := ec.Deadline()
		require.False(t, ok, "without a parent deadline the enricher's own cap applies")
	})

	t.Run("tiny remaining budget clamps enrichment to a sliver", func(t *testing.T) {
		t.Parallel()
		parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()

		ec, c := l2EnrichCtx(parent, 700*time.Millisecond)
		defer c()

		dl, ok := ec.Deadline()
		require.True(t, ok)
		// enrichBudget would be negative (300ms - 700ms) → clamped to ~1ms so
		// enrichment is effectively skipped and the sidecar keeps the remainder.
		require.Less(t, float64(time.Until(dl)), float64(50*time.Millisecond))
	})
}
