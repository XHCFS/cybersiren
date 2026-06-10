package header

import (
	"regexp"
	"strings"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

// bodyStructuralSignals are the D9 body-derived structural anomalies SVC-04
// owns. They are computed in this service (NOT the parser): per D9 the parser
// ships the body content on analysis.headers (BodyHTML + BodyPlain) and SVC-04
// derives the flags from it. See ARCH-SPEC §1 step 3b dimension (iii).
type bodyStructuralSignals struct {
	HTMLOnly        bool
	HasHiddenText   bool
	HasForm         bool
	EncodingAnomaly bool
}

// Pre-compiled patterns. Body analysis runs per-message on the hot path, so we
// compile once at init rather than per call. The patterns are deliberately
// lenient — they look for the *fingerprints* phishing kits leave, not a full
// HTML parse, which would be both slower and a new attack surface.
var (
	reHTMLTag = regexp.MustCompile(`(?is)<\s*(html|body|table|div|p|a|span|td|tr|br|img)\b`)
	reFormTag = regexp.MustCompile(`(?is)<\s*form\b`)
	reTag     = regexp.MustCompile(`(?is)<[^>]+>`)

	// Visually-hidden text fingerprints, in CSS-style or attribute form. These
	// are the classic ways a phishing message hides keyword-stuffing or hides a
	// payload from the reader while keeping it in the DOM.
	hiddenTextPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)display\s*:\s*none`),
		regexp.MustCompile(`(?is)visibility\s*:\s*hidden`),
		regexp.MustCompile(`(?is)font-size\s*:\s*0(px|pt|em|%)?\b`),
		regexp.MustCompile(`(?is)<[^>]*\shidden(\s|>|=)`),                           // HTML5 boolean hidden attribute (not the bare word in text)
		regexp.MustCompile(`(?is)(left|top|text-indent)\s*:\s*-\s*\d{3,}\s*px`),     // off-screen positioning
		regexp.MustCompile(`(?is)(width|height|max-height)\s*:\s*0(px|pt|em|%)?\b`), // zero-box
		regexp.MustCompile(`(?is)opacity\s*:\s*0(\.0+)?\b`),
	}

	reWhiteText = regexp.MustCompile(`(?is)color\s*:\s*(#?f{3,6}\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))`)
	reWhiteBg   = regexp.MustCompile(`(?is)background(-color)?\s*:\s*(#?f{3,6}\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))`)
)

// extractBodyStructural derives the D9 body structural signals from the parser-
// shipped body. It prefers the HTML part; when the message carried no HTML part
// it falls back to the plain-text body (analysis.text), per P2.3.
func extractBodyStructural(msg *contractsk.AnalysisHeadersMessage, declaredCharset string) bodyStructuralSignals {
	if msg == nil {
		return bodyStructuralSignals{}
	}

	html := msg.BodyHTML
	plain := msg.BodyPlain
	out := bodyStructuralSignals{}

	hasHTML := strings.TrimSpace(html) != "" && reHTMLTag.MatchString(html)

	// html_only: the message renders as HTML but offers no meaningful plain-
	// text alternative. Legitimate bulk senders almost always ship a multipart/
	// alternative with a real text part; HTML-only mail is a mild phishing tell.
	if hasHTML {
		out.HTMLOnly = !hasMeaningfulPlainText(plain, html)
	}

	// The remaining flags need markup to reason about. Fall back to the plain
	// body only when there is no HTML part at all (text/plain phish can still
	// declare a broken charset, hence the encoding check below also runs on it).
	markup := html
	if !hasHTML {
		markup = plain
	}

	if reFormTag.MatchString(markup) {
		out.HasForm = true
	}
	out.HasHiddenText = detectHiddenText(markup)
	out.EncodingAnomaly = detectEncodingAnomaly(declaredCharset, html, plain)

	return out
}

// hasMeaningfulPlainText reports whether the plain part carries real reader-
// facing content. An empty plain part, or one that is just the HTML stripped of
// tags down to whitespace, does NOT count — that is effectively HTML-only.
func hasMeaningfulPlainText(plain, html string) bool {
	p := strings.TrimSpace(plain)
	if p == "" {
		return false
	}
	// Some parsers synthesise a "plain" part by stripping tags; if the plain
	// body is just the tag-stripped HTML with nothing extra, treat the message
	// as HTML-only. We compare the collapsed letter/digit content.
	if normalizeBodyContent(p) == "" {
		return false
	}
	stripped := normalizeBodyContent(reTag.ReplaceAllString(html, " "))
	return normalizeBodyContent(p) != stripped || stripped == ""
}

// normalizeBodyContent lowercases and keeps only letters/digits so that
// whitespace/markup differences don't mask "same content".
func normalizeBodyContent(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func detectHiddenText(markup string) bool {
	if strings.TrimSpace(markup) == "" {
		return false
	}
	for _, re := range hiddenTextPatterns {
		if re.MatchString(markup) {
			return true
		}
	}
	// White-on-white only counts when BOTH a white text colour and a white
	// background appear — either alone is common and benign.
	if reWhiteText.MatchString(markup) && reWhiteBg.MatchString(markup) {
		return true
	}
	return false
}

// detectEncodingAnomaly flags two cheap, high-signal cases:
//  1. a declared charset the body plainly violates (declares us-ascii/iso-8859-1
//     but the body carries multibyte UTF-8 / control characters), and
//  2. an excessive ratio of non-printable control bytes, which is unusual for
//     legitimate mail and shows up in obfuscated payloads.
func detectEncodingAnomaly(declaredCharset, html, plain string) bool {
	body := html
	if strings.TrimSpace(body) == "" {
		body = plain
	}
	if strings.TrimSpace(body) == "" {
		return false
	}

	charset := strings.ToLower(strings.TrimSpace(declaredCharset))
	asciiClaim := charset == "us-ascii" || charset == "ascii" || charset == "iso-8859-1" || charset == "latin-1"
	if asciiClaim && containsNonASCII(body) {
		return true
	}

	// Control-character density (excluding the ordinary \t \n \r) above a small
	// threshold is anomalous for human-readable mail.
	var ctrl, total int
	for _, r := range body {
		total++
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			ctrl++
		}
	}
	if total == 0 {
		return false
	}
	const ctrlAnomalyRatio = 0.02
	return float64(ctrl)/float64(total) > ctrlAnomalyRatio
}
