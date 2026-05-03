package header

import "testing"

func TestDamerauLevenshtein_KnownVectors(t *testing.T) {
	t.Parallel()

	maxDist := 100
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "ab", 1},
		{"abc", "abcd", 1},
		{"abc", "abd", 1},
		{"ab", "ba", 1},  // transposition
		{"ca", "abc", 3}, // OSA: must insert 'a' or 'b' AND substitute / delete; classic OSA distance is 3.
		{"kitten", "sitting", 3},
		{"saturday", "sunday", 3},
		{"paypal", "paypa1", 1},
		{"gmail.com", "gmail.com", 0},
	}

	for _, tc := range cases {
		got := damerauLevenshtein(tc.a, tc.b, maxDist)
		if got != tc.want {
			t.Errorf("damerauLevenshtein(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDamerauLevenshtein_EarlyExit(t *testing.T) {
	t.Parallel()

	// Beyond maxDist, the function may return maxDist+1 — we just need
	// it to converge to a finite value.
	d := damerauLevenshtein("abcdefghij", "qwertyuiop", 1)
	if d <= 1 {
		t.Errorf("expected distance > 1, got %d", d)
	}
}

func TestFindTyposquat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		domain      string
		max         int
		wantTarget  string
		wantNonZero bool
	}{
		{
			name:        "exact brand → no flag",
			domain:      "paypal.com",
			max:         2,
			wantNonZero: false,
		},
		{
			name:        "single-char substitution → flagged",
			domain:      "paypa1.com",
			max:         2,
			wantTarget:  "paypal.com",
			wantNonZero: true,
		},
		{
			name:        "transposition → flagged",
			domain:      "paylap.com",
			max:         2,
			wantTarget:  "paypal.com",
			wantNonZero: true,
		},
		{
			name:        "subdomain candidate matches brand",
			domain:      "login.secure-paypa1.com",
			max:         2,
			wantTarget:  "paypal.com",
			wantNonZero: true,
		},
		{
			name:        "unrelated domain → not flagged",
			domain:      "totally-unrelated-foo.com",
			max:         2,
			wantNonZero: false,
		},
		{
			name:        "max=0 disables detection",
			domain:      "paypa1.com",
			max:         0,
			wantNonZero: false,
		},
		{
			name:        "empty input is safe",
			domain:      "",
			max:         2,
			wantNonZero: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgt, dist := FindTyposquat(tc.domain, tc.max)
			gotNonZero := dist > 0
			if gotNonZero != tc.wantNonZero {
				t.Fatalf("dist > 0 = %v, want %v (target=%q dist=%d)", gotNonZero, tc.wantNonZero, tgt, dist)
			}
			if tc.wantNonZero && tgt != tc.wantTarget {
				t.Errorf("target = %q, want %q (dist=%d)", tgt, tc.wantTarget, dist)
			}
		})
	}
}
