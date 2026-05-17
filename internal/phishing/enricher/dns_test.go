package enricher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveIP_RealHost(t *testing.T) {
	t.Skip("requires network")
	ip := ResolveIP(context.Background(), "google.com")
	require.NotEmpty(t, ip, "expected non-empty IP for google.com")
}

func TestResolveIP_InvalidHost(t *testing.T) {
	t.Parallel()
	ip := ResolveIP(context.Background(), "this.host.does.not.exist.invalid")
	require.Empty(t, ip, "expected empty string for invalid hostname")
}

func TestResolveIP_Cache(t *testing.T) {
	t.Parallel()
	// Prime the cache with a fake result.
	globalDNSCache.set("cached-test.example", "1.2.3.4")
	ip := ResolveIP(context.Background(), "cached-test.example")
	require.Equal(t, "1.2.3.4", ip)
}
