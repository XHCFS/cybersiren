package scoring

import (
	"bytes"
	"math"
	"testing"
)

func testConfig() Config {
	return Config{
		EntropyThreshold:       7.5,
		HighEntropyScore:       20,
		ExtensionMismatchScore: 30,
		DangerousExtScore:      25,
		MacroOfficeScore:       20,
		DoubleExtScore:         35,
		MaliciousHashScore:     90,
	}
}

func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy(nil); got != 0 {
		t.Fatalf("empty entropy = %v, want 0", got)
	}
	// All-identical bytes ⇒ entropy 0.
	if got := ShannonEntropy(bytes.Repeat([]byte{0x41}, 1000)); got != 0 {
		t.Fatalf("constant entropy = %v, want 0", got)
	}
	// A perfectly uniform 256-symbol distribution ⇒ entropy 8.
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	if got := ShannonEntropy(uniform); math.Abs(got-8.0) > 1e-9 {
		t.Fatalf("uniform entropy = %v, want 8", got)
	}
}

func TestScore_HighEntropy(t *testing.T) {
	cfg := testConfig()
	above := Score(Attachment{Filename: "blob.dat", Entropy: 7.9}, cfg)
	if !above.Heuristics.HighEntropy {
		t.Fatal("entropy 7.9 should fire high-entropy heuristic")
	}
	if above.Score != cfg.HighEntropyScore {
		t.Fatalf("high-entropy score = %d, want %d", above.Score, cfg.HighEntropyScore)
	}
	// Exactly at the threshold must NOT fire (strict >).
	at := Score(Attachment{Filename: "blob.dat", Entropy: 7.5}, cfg)
	if at.Heuristics.HighEntropy {
		t.Fatal("entropy == threshold should not fire")
	}
}

func TestScore_DangerousExtension(t *testing.T) {
	cfg := testConfig()
	for _, name := range []string{"setup.exe", "go.BAT", "x.scr", "loader.dll", "run.ps1"} {
		res := Score(Attachment{Filename: name}, cfg)
		if !res.Heuristics.IsDangerousExtension {
			t.Errorf("%q should be flagged dangerous", name)
		}
	}
	res := Score(Attachment{Filename: "report.pdf"}, cfg)
	if res.Heuristics.IsDangerousExtension {
		t.Error("report.pdf should not be flagged dangerous")
	}
}

func TestScore_MacroOffice(t *testing.T) {
	cfg := testConfig()
	for _, name := range []string{"invoice.docm", "sheet.XLSM", "deck.pptm"} {
		res := Score(Attachment{Filename: name}, cfg)
		if !res.Heuristics.HasMacros {
			t.Errorf("%q should be flagged macro-office", name)
		}
	}
	if Score(Attachment{Filename: "invoice.docx"}, cfg).Heuristics.HasMacros {
		t.Error("plain .docx should not be flagged as macro-enabled")
	}
}

func TestScore_DoubleExtension(t *testing.T) {
	cfg := testConfig()
	for _, name := range []string{"invoice.pdf.exe", "photo.jpg.scr", "doc.docx.bat"} {
		res := Score(Attachment{Filename: name}, cfg)
		if !res.Heuristics.DoubleExtension {
			t.Errorf("%q should be flagged double-extension", name)
		}
	}
	// A legitimate archive name must not fire (.gz is not dangerous).
	if Score(Attachment{Filename: "archive.tar.gz"}, cfg).Heuristics.DoubleExtension {
		t.Error("archive.tar.gz should not be flagged double-extension")
	}
	// Single dangerous extension is NOT a double-extension.
	if Score(Attachment{Filename: "setup.exe"}, cfg).Heuristics.DoubleExtension {
		t.Error("setup.exe should not be flagged double-extension")
	}
}

func TestScore_ExtensionMismatch(t *testing.T) {
	cfg := testConfig()
	// .pdf declared as image/png ⇒ mismatch.
	res := Score(Attachment{Filename: "doc.pdf", ContentType: "image/png"}, cfg)
	if !res.Heuristics.ExtensionMismatch {
		t.Fatal("pdf declared image/png should be a mismatch")
	}
	// Matching declared type ⇒ no mismatch.
	ok := Score(Attachment{Filename: "doc.pdf", ContentType: "application/pdf"}, cfg)
	if ok.Heuristics.ExtensionMismatch {
		t.Fatal("pdf declared application/pdf should not be a mismatch")
	}
	// charset parameter must be tolerated.
	html := Score(Attachment{Filename: "page.html", ContentType: "text/html; charset=utf-8"}, cfg)
	if html.Heuristics.ExtensionMismatch {
		t.Fatal("html with charset param should not be a mismatch")
	}
	// octet-stream is generic ⇒ not a mismatch.
	generic := Score(Attachment{Filename: "doc.pdf", ContentType: "application/octet-stream"}, cfg)
	if generic.Heuristics.ExtensionMismatch {
		t.Fatal("octet-stream declared type should not flag a mismatch")
	}
	// Archive container with a different detected payload type ⇒ skipped.
	zip := Score(Attachment{Filename: "bundle.zip", ContentType: "application/octet-stream", DetectedType: "application/x-msdownload"}, cfg)
	if zip.Heuristics.ExtensionMismatch {
		t.Fatal("archive extensions should be exempt from the mismatch heuristic")
	}
	// detected_type disagreeing with a mapped extension fires even when declared is empty.
	det := Score(Attachment{Filename: "logo.png", DetectedType: "application/x-dosexec"}, cfg)
	if !det.Heuristics.ExtensionMismatch {
		t.Fatal("png whose magic bytes are an executable should be a mismatch")
	}
	// Unknown extension ⇒ never a mismatch (we don't guess).
	unk := Score(Attachment{Filename: "data.xyz", ContentType: "image/png"}, cfg)
	if unk.Heuristics.ExtensionMismatch {
		t.Fatal("unknown extension should not flag a mismatch")
	}
}

func TestScore_SumsAndClamps(t *testing.T) {
	cfg := testConfig()
	// dangerous (.exe) + double-ext (.pdf.exe) + high entropy ⇒ 25+35+20 = 80.
	res := Score(Attachment{Filename: "invoice.pdf.exe", Entropy: 7.9}, cfg)
	if res.Score != 80 {
		t.Fatalf("combined score = %d, want 80", res.Score)
	}
	// Force a configuration that would overflow 100 to verify the clamp.
	big := Config{
		EntropyThreshold: 7.5, HighEntropyScore: 60,
		ExtensionMismatchScore: 60, DangerousExtScore: 60,
		MacroOfficeScore: 60, DoubleExtScore: 60, MaliciousHashScore: 90,
	}
	clamped := Score(Attachment{Filename: "x.pdf.exe", Entropy: 7.9, ContentType: "image/png"}, big)
	if clamped.Score != 100 {
		t.Fatalf("clamped score = %d, want 100", clamped.Score)
	}
}

func TestScore_MaliciousHashShortCircuits(t *testing.T) {
	cfg := testConfig()
	res := Score(Attachment{Filename: "clean.pdf", HashIsMalicious: true}, cfg)
	if !res.Malicious {
		t.Fatal("hash-malicious attachment should be marked malicious")
	}
	if res.Score != cfg.MaliciousHashScore {
		t.Fatalf("malicious hash score = %d, want %d", res.Score, cfg.MaliciousHashScore)
	}
	// VT malicious behaves the same.
	vt := Score(Attachment{Filename: "clean.pdf", VTMalicious: true}, cfg)
	if !vt.Malicious || vt.Score != cfg.MaliciousHashScore {
		t.Fatalf("vt-malicious: malicious=%v score=%d", vt.Malicious, vt.Score)
	}
	// Even when heuristics would otherwise score higher than 90, the hash hit
	// pins the score at exactly MaliciousHashScore (it does not stack).
	both := Score(Attachment{Filename: "x.pdf.exe", Entropy: 7.9, HashIsMalicious: true}, cfg)
	if both.Score != cfg.MaliciousHashScore {
		t.Fatalf("hash-hit score should not stack with heuristics: got %d", both.Score)
	}
}

func TestScore_BenignFile(t *testing.T) {
	cfg := testConfig()
	res := Score(Attachment{Filename: "report.pdf", ContentType: "application/pdf", Entropy: 4.2}, cfg)
	if res.Score != 0 {
		t.Fatalf("benign pdf score = %d, want 0", res.Score)
	}
	if res.Malicious {
		t.Fatal("benign pdf should not be malicious")
	}
}
