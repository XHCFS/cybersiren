package normalization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLDLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple domain", "example.com", "com"},
		{"trailing dot", "example.com.", "com"},
		{"uppercase", "EXAMPLE.COM", "com"},
		{"surrounding whitespace", "  example.com  ", "com"},
		{"subdomain", "mail.example.co.uk", "uk"},
		{"no dot", "localhost", ""},
		// IPv4 input yields the final octet; acceptable because IPs are filtered upstream.
		{"ipv4 returns last octet", "1.2.3.4", "4"},
		{"empty", "", ""},
		{"only dot", ".", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, TLDLabel(tc.input))
		})
	}
}
