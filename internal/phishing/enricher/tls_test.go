package enricher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetTLSCert_Google(t *testing.T) {
	t.Skip("requires network")
	r := GetTLSCert(context.Background(), "google.com", 443)
	require.True(t, r.Enabled)
	require.NotEmpty(t, r.Issuer)
	require.NotEmpty(t, r.Subject)
	require.NotEmpty(t, r.ValidFrom)
}

func TestGetTLSCert_InvalidHost(t *testing.T) {
	t.Parallel()
	r := GetTLSCert(context.Background(), "this.host.does.not.exist.invalid", 443)
	require.False(t, r.Enabled)
	require.Empty(t, r.Issuer)
}
