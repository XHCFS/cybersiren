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

	// Visually-hidden text fingerprints, in CSS-style or attribute form. These
	// are the classic ways a phishing message hides keyword-stuffing or hides a
	// payload from the reader while keeping it in the DOM.
	hiddenTextPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)display\s*:\s*none`),
		regexp.MustCompile(`(?is)visibility\s*:\s*hidden`),
		// font-size:0 incl. modern units. A value-terminating boundary (rather
		// than \b after the unit) is required so genuinely non-zero sizes like
		// font-size:0.5em do not match on the leading "0".
		regexp.MustCompile(`(?is)font-size\s*:\s*0(px|pt|em|rem|vh|vw|vmin|vmax|%)?(?:[;"'\s}]|$)`),
		// HTML5 boolean hidden attribute (not the bare word in text)
		regexp.MustCompile(`(?is)<[^>]*\shidden(\s|>|=)`),
		regexp.MustCompile(`(?is)(left|top|text-indent)\s*:\s*-\s*\d{3,}\s*px`), // off-screen positioning
		// zero-box. Anchored on a left boundary (so benign substrings like
		// line-height:0 / border-width:0 don't match) AND closed with the same
		// value-terminating boundary as font-size/opacity (so a fractional value
		// like width:0.5em / height:0.4em doesn't match on the leading "0").
		regexp.MustCompile(`(?is)(^|[;{\s"'])(width|height|max-height)\s*:\s*0(px|pt|em|%)?(?:[;"'\s}]|$)`),
		// genuinely-zero opacity only (0, 0.0, 0.00). A value-terminating boundary
		// keeps opacity:0.5 / 0.9 from matching on the leading "0".
		regexp.MustCompile(`(?is)opacity\s*:\s*0(\.0+)?(?:[;"'\s}]|$)`),
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

	htmlTrimmed := strings.TrimSpace(html)
	hasHTML := htmlTrimmed != "" && reHTMLTag.MatchString(html)

	// html_only: the message renders as HTML but offers no meaningful plain-text
	// alternative. SVC-02 tells us this directly via PlainSynthesised — it set
	// BodyPlain = HTMLToText(BodyHTML) because no genuine text/plain part existed —
	// so we no longer re-derive the synthesis by re-stripping the HTML with a
	// different algorithm than the parser used (which diverged on <style>/<script>
	// blocks and entities, silently dropping the signal). Legitimate bulk senders
	// ship a real text part; an HTML-only message is a mild phishing tell.
	if hasHTML {
		out.HTMLOnly = msg.PlainSynthesised
	}

	// Form / hidden-text detection runs on the HTML whenever the message carried
	// ANY HTML part — including one built only from tags outside reHTMLTag's
	// structural allowlist (a bare <form>/<input> credential-harvest payload, a
	// white-on-white <font> block), which would otherwise fall through to the
	// (often synthesised, tag-stripped) plain body and never match. Only with no
	// HTML part at all do we reason over the plain body. reHTMLTag still gates the
	// html_only decision above, which needs a recognisably-rendered document.
	markup := plain
	if htmlTrimmed != "" {
		markup = html
	}

	if reFormTag.MatchString(markup) {
		out.HasForm = true
	}
	out.HasHiddenText = detectHiddenText(markup)
	out.EncodingAnomaly = detectEncodingAnomaly(declaredCharset, html, plain)

	return out
}

// bodyCharsetOf resolves the charset SVC-04 reasons over for the encoding-anomaly
// check: the per-body-part charset SVC-02 captured (BodyCharset), falling back to
// the top-level ContentCharset for older producers / single-part messages. The
// top-level charset is empty for multipart/* mail, so without BodyCharset the
// declared-vs-observed charset signal is dead for every multipart message.
func bodyCharsetOf(msg *contractsk.AnalysisHeadersMessage) string {
	if msg == nil {
		return ""
	}
	if msg.BodyCharset != "" {
		return msg.BodyCharset
	}
	return msg.ContentCharset
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
//  1. a declared 7-bit-ASCII charset the body plainly violates (declares
//     us-ascii but the body carries non-ASCII / multibyte UTF-8 bytes), and
//  2. an excessive ratio of non-printable control bytes, which is unusual for
//     legitimate mail and shows up in obfuscated payloads.
//
// iso-8859-1 / latin-1 are deliberately NOT treated as an ASCII claim: their
// 0x80–0xFF range is legitimately printable (accented Western-European copy),
// so a body declaring iso-8859-1 with accented characters is normal mail, not
// an anomaly.
func detectEncodingAnomaly(declaredCharset, html, plain string) bool {
	body := html
	if strings.TrimSpace(body) == "" {
		body = plain
	}
	if strings.TrimSpace(body) == "" {
		return false
	}

	charset := strings.ToLower(strings.TrimSpace(declaredCharset))
	asciiClaim := charset == "us-ascii" || charset == "ascii"
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
	// Require a meaningful body length before trusting the ratio: in a very short
	// body a single stray control byte (a form-feed/ESC left by a quirky mailer)
	// dominates the ratio (1/30 = 3.3% > 2%) and trips a false anomaly. A genuine
	// obfuscated payload carries many control bytes across a longer body.
	const (
		ctrlAnomalyMinLen = 200
		ctrlAnomalyRatio  = 0.02
	)
	if total < ctrlAnomalyMinLen {
		return false
	}
	return float64(ctrl)/float64(total) > ctrlAnomalyRatio
}
