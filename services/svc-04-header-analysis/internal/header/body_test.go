package header

import (
	"strings"
	"testing"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestExtractBodyStructural_HTMLOnly(t *testing.T) {
	t.Parallel()

	// HTML part with no real plain-text alternative => html_only.
	msg := &contractsk.AnalysisHeadersMessage{
		BodyHTML: `<html><body><p>Click <a href="http://x">here</a></p></body></html>`,
	}
	got := extractBodyStructural(msg, "")
	if !got.HTMLOnly {
		t.Errorf("expected HTMLOnly=true with no plain part")
	}

	// Same HTML but with a genuine, distinct plain part => NOT html_only.
	msg.BodyPlain = "Hello, please review the attached invoice and reply by Friday."
	got = extractBodyStructural(msg, "")
	if got.HTMLOnly {
		t.Errorf("expected HTMLOnly=false when a meaningful plain part exists")
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

func TestExtractBodyStructural_HTMLOnlySynthesisedPlain(t *testing.T) {
	t.Parallel()

	// SVC-02 synthesises BodyPlain from the HTML when the message had no genuine
	// text/plain part (parser.go: BodyPlain = HTMLToText(html)), so a "plain" part
	// whose words equal the stripped HTML means the message is effectively
	// HTML-only and MUST be flagged. (A genuine, DISTINCT plain alternative is
	// covered by TestExtractBodyStructural_HTMLOnly above and is NOT flagged.)
	sentence := "Your invoice is ready, please sign in to review it."
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  "<html><body><p>" + sentence + "</p></body></html>",
		BodyPlain: sentence,
	}, "")
	if !got.HTMLOnly {
		t.Errorf("a plain part that merely mirrors the stripped HTML is the synthesised HTML-only case and must be flagged")
	}

	// A whitespace-only "plain" part alongside HTML is the synthesised-empty case
	// and MUST still be flagged HTML-only.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  "<html><body><p>" + sentence + "</p></body></html>",
		BodyPlain: "   \n\t  ",
	}, "")
	if !got.HTMLOnly {
		t.Errorf("a whitespace-only plain part with HTML must be flagged HTMLOnly")
	}

	// A "plain" part that is only markup with no letters/digits collapses to empty
	// and is likewise the effectively-empty (HTML-only) case.
	got = extractBodyStructural(&contractsk.AnalysisHeadersMessage{
		BodyHTML:  "<html><body><p>" + sentence + "</p></body></html>",
		BodyPlain: "<><>  <>",
	}, "")
	if !got.HTMLOnly {
		t.Errorf("a no-letters plain part with HTML must be flagged HTMLOnly")
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
	// A burst of NUL/control bytes is anomalous for human-readable mail.
	body := "hi" + strings.Repeat("\x00\x01\x02", 50)
	got := extractBodyStructural(&contractsk.AnalysisHeadersMessage{BodyPlain: body}, "utf-8")
	if !got.EncodingAnomaly {
		t.Errorf("expected EncodingAnomaly for high control-char density")
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
