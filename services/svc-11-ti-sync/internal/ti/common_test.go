package ti_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
)

func TestDeduplicateTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no duplicates",
			in:   []string{"exe", "RAT", "malwarebazaar"},
			want: []string{"exe", "RAT", "malwarebazaar"},
		},
		{
			name: "exact duplicate",
			in:   []string{"exe", "RAT", "malwarebazaar", "exe"},
			want: []string{"exe", "RAT", "malwarebazaar"},
		},
		{
			name: "case-insensitive duplicate preserves first",
			in:   []string{"EXE", "rat", "malwarebazaar", "exe"},
			want: []string{"EXE", "rat", "malwarebazaar"},
		},
		{
			name: "empty slice",
			in:   []string{},
			want: []string{},
		},
		{
			name: "nil slice",
			in:   nil,
			want: []string{},
		},
		{
			name: "all duplicates",
			in:   []string{"a", "A", "a"},
			want: []string{"a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ti.DeduplicateTags(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
