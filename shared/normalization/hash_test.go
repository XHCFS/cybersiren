package normalization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidHexHash(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		hexLen int
		want   bool
	}{
		{"valid sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 64, true},
		{"valid md5", "d41d8cd98f00b204e9800998ecf8427e", 32, true},
		{"too short", "abcdef", 64, false},
		{"too long", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aa", 64, false},
		{"uppercase chars", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", 64, false},
		{"non-hex chars", "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 64, false},
		{"spaces", " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", 64, false},
		{"empty", "", 64, false},
		{"empty zero len", "", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidHexHash(tc.input, tc.hexLen))
		})
	}
}
