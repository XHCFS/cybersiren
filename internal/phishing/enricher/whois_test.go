package enricher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookupWHOIS_RealDomain(t *testing.T) {
	t.Skip("requires network and WHOIS access")
	r := LookupWHOIS(context.Background(), "google.com")
	require.NotEmpty(t, r.RegistrationDate, "google.com should have a creation date")
}

func TestLookupWHOIS_GarbageInput(t *testing.T) {
	t.Parallel()
	r := LookupWHOIS(context.Background(), "this-is-not-a-real-domain-xyz-abc-123.invalid")
	require.Empty(t, r.RegistrationDate)
	require.Empty(t, r.Registrar)
}

func TestLookupWHOIS_Cache(t *testing.T) {
	t.Parallel()
	fake := WHOISResult{RegistrationDate: "2000-01-01", Registrar: "Test Registrar"}
	globalWHOISCache.set("cached-whois.test", fake)
	r := LookupWHOIS(context.Background(), "cached-whois.test")
	require.Equal(t, fake, r)
}
