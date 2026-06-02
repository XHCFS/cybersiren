package email

import (
	"strings"
	"testing"
)

func TestExtractURLsFromHTML(t *testing.T) {
	body := `<html><body>
		<a href="https://login.example.com/reset">Click Here</a>
		<img src="https://tracker.example.net/pixel.gif">
		<form action="https://collect.example.org/submit"></form>
		<a href="/relative/path">ignored relative</a>
		<a href="javascript:void(0)">ignored js</a>
	</body></html>`

	urls := ExtractURLsFromHTML(body)
	got := map[string]string{}
	for _, u := range urls {
		got[u.URL] = u.VisibleText
	}

	if vt, ok := got["https://login.example.com/reset"]; !ok || vt != "Click Here" {
		t.Errorf("anchor href/visible-text = %q,%v; want Click Here", vt, ok)
	}
	if _, ok := got["https://tracker.example.net/pixel.gif"]; !ok {
		t.Errorf("img src not extracted: %v", got)
	}
	if _, ok := got["https://collect.example.org/submit"]; !ok {
		t.Errorf("form action not extracted: %v", got)
	}
	if len(urls) != 3 {
		t.Errorf("got %d urls, want 3 (relative + javascript dropped): %v", len(urls), got)
	}
}

func TestExtractMetaRefreshURL(t *testing.T) {
	body := `<html><head>
		<meta http-equiv="refresh" content="5; url=https://evil.example.com/landing">
	</head><body>redirecting</body></html>`

	urls := ExtractURLsFromHTML(body)
	if len(urls) != 1 || urls[0].URL != "https://evil.example.com/landing" {
		t.Fatalf("meta-refresh extraction = %v, want the landing URL", urls)
	}
}

func TestStripHTMLRemovesScriptAndStyle(t *testing.T) {
	body := `<html><head><style>.x{color:red}</style></head>
		<body><script>alert('xss')</script><p>Hello <b>world</b></p></body></html>`

	got := StripHTML(body)
	if strings.Contains(got, "alert") || strings.Contains(got, "color:red") {
		t.Errorf("StripHTML left script/style content: %q", got)
	}
	if got != "Hello world" {
		t.Errorf("StripHTML = %q, want %q", got, "Hello world")
	}
}

func TestFinalizeUsesHTMLBody(t *testing.T) {
	raw := "From: a@example.com\r\n" +
		"Subject: html only\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		`<html><body><a href="https://x.example.com/a">go</a><script>1</script> visible text</body></html>` + "\r\n"

	pe, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pe.URLs) != 1 || pe.URLs[0].URL != "https://x.example.com/a" || pe.URLs[0].VisibleText != "go" {
		t.Errorf("URLs = %+v, want one anchor with visible text", pe.URLs)
	}
	if strings.Contains(pe.BodyPlain, "<a") || !strings.Contains(pe.BodyPlain, "visible text") {
		t.Errorf("BodyPlain = %q, want stripped text", pe.BodyPlain)
	}
}
