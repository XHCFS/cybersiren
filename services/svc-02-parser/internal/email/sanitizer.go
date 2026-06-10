// HTML → clean plain text sanitization for the NLP body (analysis.text) and
// the body_plain column. Per ARCH-SPEC §1 step 2 the parser strips HTML to a
// clean plain-text rendering; per D9 it does NOT compute structural flags
// (html_only / has_hidden_text / has_form / encoding anomalies) — those are
// SVC-04's to derive from the body content the parser ships.
package email

import (
	"strings"
	"unicode"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// nonContentElements are HTML elements whose text content is markup/metadata,
// not human-readable body text, and must be dropped entirely when rendering to
// plain text (including their descendants).
var nonContentElements = map[atom.Atom]struct{}{
	atom.Script:   {},
	atom.Style:    {},
	atom.Head:     {},
	atom.Title:    {},
	atom.Noscript: {},
	atom.Template: {},
}

// blockElements introduce a line break when rendered to plain text so that
// paragraph/structure boundaries survive the strip (helps downstream word
// counting and readability without leaking markup).
var blockElements = map[atom.Atom]struct{}{
	atom.P: {}, atom.Br: {}, atom.Div: {}, atom.Tr: {}, atom.Li: {},
	atom.H1: {}, atom.H2: {}, atom.H3: {}, atom.H4: {}, atom.H5: {}, atom.H6: {},
	atom.Table: {}, atom.Ul: {}, atom.Ol: {}, atom.Blockquote: {}, atom.Hr: {},
	atom.Section: {}, atom.Article: {}, atom.Header: {}, atom.Footer: {},
}

// HTMLToText renders an HTML document/fragment to clean plain text. It drops
// script/style/head content, inserts newlines at block boundaries, unescapes
// entities (handled by the tokenizer), and collapses runs of whitespace. On a
// parse failure it falls back to a tag-stripping pass so a malformed body still
// yields usable text rather than an empty string.
func HTMLToText(htmlBody string) string {
	if strings.TrimSpace(htmlBody) == "" {
		return ""
	}

	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return collapseWhitespace(stripTagsFallback(htmlBody))
	}

	var b strings.Builder
	renderText(&b, doc)
	return collapseWhitespace(b.String())
}

// renderText walks the parse tree depth-first, appending text nodes and block
// separators, skipping non-content subtrees entirely.
func renderText(b *strings.Builder, n *html.Node) {
	if n.Type == html.ElementNode {
		if _, skip := nonContentElements[n.DataAtom]; skip {
			return
		}
	}

	if n.Type == html.TextNode {
		b.WriteString(n.Data)
	}

	isBlock := n.Type == html.ElementNode
	if isBlock {
		_, isBlock = blockElements[n.DataAtom]
	}
	if isBlock {
		b.WriteByte('\n')
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		renderText(b, c)
	}

	if isBlock {
		b.WriteByte('\n')
	}
}

// stripTagsFallback removes everything between < and > as a last resort when
// the HTML tokenizer cannot parse the input at all.
func stripTagsFallback(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// collapseWhitespace trims the string and collapses every run of whitespace
// (including the block-boundary newlines we inserted) to a single space, so the
// NLP body is a clean, normalized token stream.
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := true // leading-trim: treat start as if preceded by space
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimRight(b.String(), " ")
}

// WordCount counts whitespace-delimited tokens in s (the cleaned plain text).
func WordCount(s string) int {
	return len(strings.Fields(s))
}
