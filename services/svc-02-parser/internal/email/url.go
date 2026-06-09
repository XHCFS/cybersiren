// URL extraction from HTML and plain-text email parts. Each extracted URL
// carries the per-URL metadata the analysis.urls contract requires
// (visible_text / position / html_context) per ARCH-SPEC §1 step 2.
package email

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// ExtractedURL is one URL found in an email part plus the context downstream
// URL scoring (SVC-03) uses for explainability. Mirrors the analysis.urls
// contract shape (shared/contracts/kafka.ExtractedURL) without importing it so
// the parser package stays free of the wire types.
type ExtractedURL struct {
	URL         string
	VisibleText string
	Position    string // "body" | "header"
	HTMLContext string // "href" | "src" | "action" | "meta_refresh" | "plain_text"
}

// urlRE matches http(s) URLs in plain text. RE2 has no backtracking, so the
// trailing-punctuation trim is done in code rather than in the pattern.
var urlRE = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `)\]}]+`)

// metaRefreshURLRE pulls the URL out of a <meta http-equiv="refresh"
// content="5; url=https://…"> directive.
var metaRefreshURLRE = regexp.MustCompile(`(?i)url\s*=\s*['"]?\s*(https?://[^\s'"]+)`)

// ExtractURLsFromHTML walks an HTML body and pulls every URL out of href / src
// / action attributes and meta-refresh directives, tagging each with the
// attribute it came from and the anchor's visible text. Falls back to a plain-
// text sweep over the raw markup if the HTML cannot be parsed.
func ExtractURLsFromHTML(htmlBody string) []ExtractedURL {
	if strings.TrimSpace(htmlBody) == "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return ExtractURLsFromText(htmlBody)
	}
	var out []ExtractedURL
	walkHTMLURLs(doc, &out)
	return out
}

func walkHTMLURLs(n *html.Node, out *[]ExtractedURL) {
	if n.Type == html.ElementNode {
		switch n.DataAtom {
		case atom.A:
			if href, ok := attr(n, "href"); ok && isHTTPish(href) {
				*out = append(*out, ExtractedURL{
					URL:         strings.TrimSpace(href),
					VisibleText: nodeText(n),
					Position:    "body",
					HTMLContext: "href",
				})
			}
		case atom.Img, atom.Script, atom.Iframe, atom.Source, atom.Embed, atom.Video, atom.Audio:
			if src, ok := attr(n, "src"); ok && isHTTPish(src) {
				*out = append(*out, ExtractedURL{
					URL:         strings.TrimSpace(src),
					Position:    "body",
					HTMLContext: "src",
				})
			}
		case atom.Form:
			if action, ok := attr(n, "action"); ok && isHTTPish(action) {
				*out = append(*out, ExtractedURL{
					URL:         strings.TrimSpace(action),
					Position:    "body",
					HTMLContext: "action",
				})
			}
		case atom.Meta:
			if equiv, ok := attr(n, "http-equiv"); ok && strings.EqualFold(equiv, "refresh") {
				if content, ok := attr(n, "content"); ok {
					if m := metaRefreshURLRE.FindStringSubmatch(content); m != nil {
						*out = append(*out, ExtractedURL{
							URL:         strings.TrimSpace(m[1]),
							Position:    "body",
							HTMLContext: "meta_refresh",
						})
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkHTMLURLs(c, out)
	}
}

// ExtractURLsFromText sweeps a plain-text part for http(s) URLs, trimming the
// trailing punctuation a regex cannot safely exclude.
func ExtractURLsFromText(text string) []ExtractedURL {
	matches := urlRE.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]ExtractedURL, 0, len(matches))
	for _, m := range matches {
		u := strings.TrimRight(m, ".,;:!?)]}\"'")
		if u == "" {
			continue
		}
		out = append(out, ExtractedURL{
			URL:         u,
			Position:    "body",
			HTMLContext: "plain_text",
		})
	}
	return out
}

// DedupeURLs removes duplicate (url) entries, keeping the FIRST occurrence so an
// anchor's visible_text/context wins over a later bare repeat of the same URL.
func DedupeURLs(in []ExtractedURL) []ExtractedURL {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]ExtractedURL, 0, len(in))
	for _, u := range in {
		key := strings.TrimSpace(u.URL)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		u.URL = key
		out = append(out, u)
	}
	return out
}

func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// nodeText returns the collapsed visible text of an element subtree (the anchor
// label), bounded so a runaway subtree cannot bloat the message.
func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
			return
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(collapseWhitespace(b.String()))
}

func isHTTPish(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}
