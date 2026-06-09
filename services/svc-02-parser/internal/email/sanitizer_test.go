package email

import (
	"strings"
	"testing"
)

func TestHTMLToText(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		contains []string
		excludes []string
	}{
		{
			name:     "strips tags and keeps text",
			html:     `<html><body><p>Hello <b>world</b></p></body></html>`,
			contains: []string{"Hello", "world"},
			excludes: []string{"<p>", "<b>", "<body>"},
		},
		{
			name:     "drops script and style content",
			html:     `<html><head><style>.a{color:red}</style></head><body><script>alert(1)</script><p>visible</p></body></html>`,
			contains: []string{"visible"},
			excludes: []string{"alert", "color:red", ".a{"},
		},
		{
			name:     "unescapes entities",
			html:     `<p>Tom &amp; Jerry &lt;3</p>`,
			contains: []string{"Tom & Jerry <3"},
		},
		{
			name:     "collapses whitespace",
			html:     "<p>a   b\n\n\tc</p>",
			contains: []string{"a b c"},
		},
		{
			name:     "malformed html still yields text",
			html:     `<p>unclosed <b>bold text`,
			contains: []string{"unclosed", "bold text"},
			excludes: []string{"<b>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HTMLToText(tt.html)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("HTMLToText() = %q, want contains %q", got, want)
				}
			}
			for _, no := range tt.excludes {
				if strings.Contains(got, no) {
					t.Errorf("HTMLToText() = %q, want NOT contains %q", got, no)
				}
			}
		})
	}
}

func TestHTMLToTextEmpty(t *testing.T) {
	if got := HTMLToText(""); got != "" {
		t.Errorf("HTMLToText(\"\") = %q, want empty", got)
	}
	if got := HTMLToText("   \n\t "); got != "" {
		t.Errorf("HTMLToText(whitespace) = %q, want empty", got)
	}
}

func TestWordCount(t *testing.T) {
	cases := map[string]int{
		"":              0,
		"one":           1,
		"one two three": 3,
		"  pad   words ": 2,
	}
	for in, want := range cases {
		if got := WordCount(in); got != want {
			t.Errorf("WordCount(%q) = %d, want %d", in, got, want)
		}
	}
}
