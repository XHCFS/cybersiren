package producer

import "testing"

func TestNormalizePublishAttempts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		retries int
		want    int
	}{
		{retries: 0, want: 1},
		{retries: 1, want: 2},
		{retries: 3, want: 4},
		{retries: -1, want: 1},
		{retries: -5, want: 1},
	}
	for _, tc := range cases {
		if got := normalizePublishAttempts(tc.retries); got != tc.want {
			t.Errorf("retries=%d: got %d want %d", tc.retries, got, tc.want)
		}
	}
}
