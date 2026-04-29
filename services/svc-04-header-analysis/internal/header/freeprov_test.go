package header

import "testing"

func TestIsFreeProvider(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"":                     false,
		"gmail.com":            true,
		"GMAIL.COM":            true,
		"  gmail.com  ":        true,
		"gmail.com.":           true,
		"users.gmail.com":      true,
		"corp.example.com":     false,
		"yahoo.co.jp":          true,
		"ru.mail.ru":           true,
		"some-other.example":   false,
		"protonmail.com":       true,
		"alias.protonmail.com": true,
	}
	for in, want := range cases {
		got := IsFreeProvider(in)
		if got != want {
			t.Errorf("IsFreeProvider(%q) = %v, want %v", in, got, want)
		}
	}
}
