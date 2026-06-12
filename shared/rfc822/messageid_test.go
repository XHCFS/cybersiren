package rfc822

import "testing"

func TestMessageID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "header present with angle brackets is trimmed",
			raw:  "From: a@b.test\r\nMessage-ID: <id-1@b.test>\r\nSubject: hi\r\n\r\nbody",
			want: "id-1@b.test",
		},
		{
			name: "header present without angle brackets is returned verbatim",
			raw:  "From: a@b.test\r\nMessage-Id: id-2@b.test\r\nSubject: hi\r\n\r\nbody",
			want: "id-2@b.test",
		},
		{
			name: "header absent yields empty",
			raw:  "From: a@b.test\r\nSubject: hi\r\n\r\nbody",
			want: "",
		},
		{
			name: "unparseable message yields empty (not deduplicated)",
			raw:  "not a valid email",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := MessageID([]byte(tc.raw)); got != tc.want {
				t.Errorf("MessageID() = %q, want %q", got, tc.want)
			}
		})
	}
}
