package enricher

import (
	"context"
	"errors"
	"net"
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
	globalDNSCache.set("cached-test.example", "1.2.3.4", dnsCacheTTL)
	ip := ResolveIP(context.Background(), "cached-test.example")
	require.Equal(t, "1.2.3.4", ip)
}

func TestIsDNSNetworkError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error is not a network error", nil, false},
		{"NXDOMAIN (host not found) is not a network error", &net.DNSError{IsNotFound: true}, false},
		{"DNS timeout is a network error", &net.DNSError{IsTimeout: true}, true},
		{"DNS temporary failure is a network error", &net.DNSError{IsTemporary: true}, true},
		{"bare DNSError (SERVFAIL) is a network error", &net.DNSError{}, true},
		{"context deadline exceeded is a network error", context.DeadlineExceeded, true},
		{"generic error is a network error", errors.New("dial udp: connect: network is unreachable"), true},
		{"wrapped NXDOMAIN is not a network error", errWrap(&net.DNSError{IsNotFound: true}), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, isDNSNetworkError(tc.err))
		})
	}
}

func errWrap(err error) error { return errors.Join(errors.New("lookup failed"), err) }
