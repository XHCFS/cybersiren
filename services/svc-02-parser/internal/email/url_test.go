package email

import "testing"

func TestExtractURLsFromHTML(t *testing.T) {
	html := `
<html><body>
  <a href="https://anchor.example.com/login">Click here</a>
  <img src="https://img.example.com/pixel.gif"/>
  <form action="https://phish.example.com/submit"><input/></form>
  <meta http-equiv="refresh" content="0; url=https://redirect.example.com/go">
  <a href="mailto:nope@example.com">mail</a>
  <a href="/relative/path">relative</a>
</body></html>`

	got := ExtractURLsFromHTML(html)
	byURL := map[string]ExtractedURL{}
	for _, u := range got {
		byURL[u.URL] = u
	}

	tests := []struct {
		url     string
		context string
		visible string
	}{
		{"https://anchor.example.com/login", "href", "Click here"},
		{"https://img.example.com/pixel.gif", "src", ""},
		{"https://phish.example.com/submit", "action", ""},
		{"https://redirect.example.com/go", "meta_refresh", ""},
	}
	for _, tt := range tests {
		u, ok := byURL[tt.url]
		if !ok {
			t.Fatalf("expected URL %q not extracted; got %+v", tt.url, got)
		}
		if u.HTMLContext != tt.context {
			t.Errorf("%q html_context = %q, want %q", tt.url, u.HTMLContext, tt.context)
		}
		if u.VisibleText != tt.visible {
			t.Errorf("%q visible_text = %q, want %q", tt.url, u.VisibleText, tt.visible)
		}
		if u.Position != "body" {
			t.Errorf("%q position = %q, want body", tt.url, u.Position)
		}
	}

	// mailto: and relative hrefs must be ignored (not http(s)).
	if _, ok := byURL["mailto:nope@example.com"]; ok {
		t.Error("mailto: link should not be extracted")
	}
	if _, ok := byURL["/relative/path"]; ok {
		t.Error("relative href should not be extracted")
	}
}

func TestExtractURLsFromText(t *testing.T) {
	text := "Visit https://example.com/a, and http://foo.test/b. Also (https://bar.test/c)."
	got := ExtractURLsFromText(text)
	want := map[string]bool{
		"https://example.com/a": true,
		"http://foo.test/b":     true,
		"https://bar.test/c":    true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d urls, want %d: %+v", len(got), len(want), got)
	}
	for _, u := range got {
		if !want[u.URL] {
			t.Errorf("unexpected/untrimmed url %q", u.URL)
		}
		if u.HTMLContext != "plain_text" {
			t.Errorf("%q html_context = %q, want plain_text", u.URL, u.HTMLContext)
		}
	}
}

func TestDedupeURLsKeepsFirst(t *testing.T) {
	in := []ExtractedURL{
		{URL: "https://x.test", VisibleText: "anchor", HTMLContext: "href"},
		{URL: "https://x.test", HTMLContext: "plain_text"},
		{URL: "https://y.test", HTMLContext: "src"},
		{URL: "", HTMLContext: "href"},
	}
	got := DedupeURLs(in)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if got[0].URL != "https://x.test" || got[0].VisibleText != "anchor" {
		t.Errorf("first occurrence (with visible_text) should win: %+v", got[0])
	}
}
