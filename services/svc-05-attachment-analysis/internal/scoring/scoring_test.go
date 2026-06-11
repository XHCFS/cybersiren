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

func TestScore_TrailingDotSpaceDoesNotDefeatHeuristics(t *testing.T) {
	cfg := testConfig()
	// S1: Windows strips trailing dots/whitespace when resolving a filename, so
	// "invoice.exe." / "invoice.exe " execute as "invoice.exe". path.Ext on the raw
	// name yields "." / ".exe " (in no ext set), silently zeroing every heuristic.
	// extOf must normalise them back to ".exe".
	for _, name := range []string{"invoice.exe.", "invoice.exe ", "invoice.exe\t", "INVOICE.EXE.", "loader.scr.  "} {
		res := Score(Attachment{Filename: name}, cfg)
		if !res.Heuristics.IsDangerousExtension {
			t.Errorf("%q: expected dangerous-extension despite trailing dot/space", name)
		}
		if res.Score < cfg.DangerousExtScore {
			t.Errorf("%q: score = %d, want >= %d", name, res.Score, cfg.DangerousExtScore)
		}
	}
	// Macro-office and double-extension lures with trailing noise still fire.
	if !Score(Attachment{Filename: "invoice.docm."}, cfg).Heuristics.HasMacros {
		t.Error("invoice.docm. : expected macro-office despite trailing dot")
	}
	if !Score(Attachment{Filename: "invoice.pdf.exe "}, cfg).Heuristics.DoubleExtension {
		t.Error("invoice.pdf.exe (trailing space): expected double-extension")
	}
	// A genuinely benign name with a trailing dot stays benign.
	if Score(Attachment{Filename: "report.pdf."}, cfg).Heuristics.IsDangerousExtension {
		t.Error("report.pdf. must not be flagged dangerous")
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

// TestScore_ExtensionMismatch_ContainerAndCoarseTypes locks the F1 fix: the
// magic-byte sniffer reports COARSE container/charset-blind types for whole
// families of legitimate documents (OOXML as application/zip, legacy Office as
// application/x-ole-storage, json/csv/xml as text/plain). None of those may trip
// extension_mismatch, while a genuine type swap still does.
func TestScore_ExtensionMismatch_ContainerAndCoarseTypes(t *testing.T) {
	cfg := testConfig()

	noMismatch := []struct {
		name         string
		filename     string
		contentType  string
		detectedType string
	}{
		// OOXML: declared the specific type, sniffed as the zip container.
		{"docx", "report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
		{"xlsx", "sheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
		{"pptx", "deck.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"},
		// OOXML where the sender mislabels content_type as the generic zip type too.
		{"docx-declared-zip", "report.docx", "application/zip", "application/zip"},
		// Legacy Office: sniffed as the OLE compound-document container.
		{"doc", "letter.doc", "application/msword", "application/x-ole-storage"},
		{"xls", "book.xls", "application/vnd.ms-excel", "application/x-ole-storage"},
		{"ppt", "slides.ppt", "application/vnd.ms-powerpoint", "application/x-ole-storage"},
		// Text-family formats sniff to the coarse text/plain.
		{"json", "data.json", "application/json", "text/plain"},
		{"csv", "rows.csv", "text/csv", "text/plain"},
		{"xml", "doc.xml", "application/xml", "text/plain"},
	}
	for _, tc := range noMismatch {
		t.Run("no_mismatch/"+tc.name, func(t *testing.T) {
			res := Score(Attachment{Filename: tc.filename, ContentType: tc.contentType, DetectedType: tc.detectedType}, cfg)
			if res.Heuristics.ExtensionMismatch {
				t.Fatalf("%s (declared=%q detected=%q) must NOT flag extension_mismatch",
					tc.filename, tc.contentType, tc.detectedType)
			}
		})
	}

	// True positives must still fire.
	fires := []struct {
		name         string
		filename     string
		contentType  string
		detectedType string
	}{
		// A .pdf whose magic bytes are a PNG image is a genuine swap.
		{"pdf-detected-png", "doc.pdf", "application/pdf", "image/png"},
		// A .pdf declared as a Windows executable is a genuine swap.
		{"pdf-declared-exe", "doc.pdf", "application/x-msdownload", "application/x-msdownload"},
		// A .docx whose bytes are an OLE container (not a zip) is still suspect:
		// ole is the coarse type for legacy Office, not OOXML.
		{"docx-detected-ole", "report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/x-ole-storage"},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			res := Score(Attachment{Filename: tc.filename, ContentType: tc.contentType, DetectedType: tc.detectedType}, cfg)
			if !res.Heuristics.ExtensionMismatch {
				t.Fatalf("%s (declared=%q detected=%q) SHOULD flag extension_mismatch",
					tc.filename, tc.contentType, tc.detectedType)
			}
		})
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
