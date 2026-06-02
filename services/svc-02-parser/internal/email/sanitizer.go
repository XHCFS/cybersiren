package email

import (
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// ExtractURLsFromHTML parses an HTML body and returns every navigable URL it
// references: anchor href targets (with their visible text), media/script src
// targets, form action targets, and meta-refresh redirects. Only absolute
// http(s) URLs are returned — relative links and javascript: handlers are
// dropped because they carry no standalone reputation signal.
func ExtractURLsFromHTML(htmlBody string) []ExtractedURL {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil
	}

	var out []ExtractedURL
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.A:
				if href := attrValue(n, "href"); isHTTPURL(href) {
					out = append(out, ExtractedURL{URL: href, VisibleText: nodeText(n)})
				}
			case atom.Img, atom.Script, atom.Iframe, atom.Source, atom.Embed, atom.Video, atom.Audio:
				if src := attrValue(n, "src"); isHTTPURL(src) {
					out = append(out, ExtractedURL{URL: src})
				}
			case atom.Form:
				if action := attrValue(n, "action"); isHTTPURL(action) {
					out = append(out, ExtractedURL{URL: action})
				}
			case atom.Meta:
				if u := metaRefreshURL(n); isHTTPURL(u) {
					out = append(out, ExtractedURL{URL: u})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// StripHTML renders an HTML body down to its visible text. <script> and <style>
// subtrees are dropped entirely so their contents never reach the NLP model,
// and runs of whitespace are collapsed to single spaces.
func StripHTML(htmlBody string) string {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return htmlBody
	}

	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.DataAtom == atom.Script || n.DataAtom == atom.Style) {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return strings.Join(strings.Fields(b.String()), " ")
}

// attrValue returns the trimmed value of the named attribute, or "" if absent.
func attrValue(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// nodeText concatenates the whitespace-collapsed text content of a subtree.
func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// metaRefreshURL extracts the redirect target from a
// <meta http-equiv="refresh" content="N; url=..."> element, or "" when the node
// is not a refresh directive.
func metaRefreshURL(n *html.Node) string {
	if !strings.EqualFold(attrValue(n, "http-equiv"), "refresh") {
		return ""
	}
	for _, part := range strings.Split(attrValue(n, "content"), ";") {
		part = strings.TrimSpace(part)
		if len(part) >= 4 && strings.EqualFold(part[:4], "url=") {
			return strings.Trim(strings.TrimSpace(part[4:]), `'"`)
		}
	}
	return ""
}

// isHTTPURL reports whether s is an absolute http or https URL.
func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
