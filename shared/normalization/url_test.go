package normalization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{
			name:    "empty input",
			raw:     "   ",
			wantErr: ErrEmptyURL,
		},
		{
			name: "missing scheme",
			raw:  "Example.com",
			want: "http://example.com",
		},
		{
			name: "trailing slash root",
			raw:  "https://Example.COM/",
			want: "https://example.com",
		},
		{
			name: "uppercase with path query",
			raw:  "HTTPS://EXAMPLE.COM/Path/File?Q=VaL",
			want: "https://example.com/Path/File?Q=VaL",
		},
		{
			name:    "invalid url",
			raw:     "http://[::1",
			wantErr: ErrInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeURL(tt.raw)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr error
	}{
		{
			name:    "empty input",
			rawURL:  "",
			wantErr: ErrEmptyDomain,
		},
		{
			name:    "missing scheme",
			rawURL:  "example.com/path",
			wantErr: ErrEmptyDomain,
		},
		{
			name:   "valid with path query",
			rawURL: "https://EXAMPLE.com:8443/Some/Path?A=B",
			want:   "example.com",
		},
		{
			name:    "invalid url",
			rawURL:  "http://[::1",
			wantErr: ErrInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractDomain(tt.rawURL)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty",
			raw:  "",
			want: "",
		},
		{
			name: "wildcard and trailing dot",
			raw:  "  *.Example.COM. ",
			want: "example.com",
		},
		{
			name: "uppercase plain domain",
			raw:  "EXAMPLE.ORG",
			want: "example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDomain(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "empty input",
			raw:  "",
			want: false,
		},
		{
			name: "valid https with path query",
			raw:  "https://Example.com/Path?A=B",
			want: true,
		},
		{
			name: "missing scheme",
			raw:  "example.com/path",
			want: false,
		},
		{
			name: "non http scheme",
			raw:  "ftp://example.com/file",
			want: false,
		},
		{
			name: "invalid url",
			raw:  "http://[::1",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsURL(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}
