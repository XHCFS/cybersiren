// Package analyzer scores email attachments for malware risk. The scoring is
// pure (no I/O): the caller supplies the attachment metadata + the
// attachment_library fields (is_malicious, entropy, magic-byte extension) and
// gets back a 0..100 risk score plus the reasons that drove it. Point values
// follow ARCH-SPEC Step 3c.
package analyzer

import "strings"

// Point values for each signal (ARCH-SPEC Step 3c).
const (
	scoreMalicious = 90 // known-bad hash short-circuits to this
	scoreEntropy   = 20 // Shannon entropy > entropyThreshold
	scoreMismatch  = 30 // declared extension disagrees with Content-Type
	scoreDangerous = 25 // executable / script extension
	scoreMacro     = 20 // macro-enabled Office document
	scoreDoubleExt = 35 // disguised double extension, e.g. invoice.pdf.exe
	maxScore       = 100

	entropyThreshold = 7.5
)

// dangerousExts are executable / script extensions that should never arrive as
// email attachments.
var dangerousExts = map[string]bool{
	"exe": true, "scr": true, "bat": true, "ps1": true, "vbs": true,
	"js": true, "wsf": true, "hta": true, "cmd": true,
}

// macroOfficeExts are the macro-enabled OOXML document extensions.
var macroOfficeExts = map[string]bool{"docm": true, "xlsm": true, "pptm": true}

// extMIME maps a file extension to the Content-Type values that are legitimate
// for it. A declared type outside this set (when the extension is known) is a
// mismatch. Kept deliberately small/curated to avoid false positives.
var extMIME = map[string][]string{
	"pdf":  {"application/pdf"},
	"zip":  {"application/zip", "application/x-zip-compressed"},
	"doc":  {"application/msword"},
	"docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	"xls":  {"application/vnd.ms-excel"},
	"xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	"png":  {"image/png"},
	"jpg":  {"image/jpeg"},
	"jpeg": {"image/jpeg"},
	"gif":  {"image/gif"},
	"txt":  {"text/plain"},
	"html": {"text/html"},
	"csv":  {"text/csv", "application/csv"},
}

// Attachment is the scoring input: wire metadata plus the attachment_library
// fields resolved by sha256.
type Attachment struct {
	Filename        string
	ContentType     string
	SHA256          string
	IsMalicious     bool
	Entropy         float64
	ActualExtension string
	SizeBytes       int64
}

// Result is the score plus the labels of the signals that fired.
type Result struct {
	Score   int
	Reasons []string
}

// Score computes the risk score for one attachment. A known-malicious hash
// short-circuits to scoreMalicious; otherwise the heuristic points are summed
// and capped at 100.
func Score(a Attachment) Result {
	if a.IsMalicious {
		return Result{Score: scoreMalicious, Reasons: []string{"malicious_hash"}}
	}

	ext := fileExt(a.Filename)
	score := 0
	var reasons []string
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}

	if a.Entropy > entropyThreshold {
		add(scoreEntropy, "high_entropy")
	}
	if extMIMEMismatch(ext, a.ContentType) {
		add(scoreMismatch, "ext_mime_mismatch")
	}
	if dangerousExts[ext] {
		add(scoreDangerous, "dangerous_ext")
	}
	if macroOfficeExts[ext] {
		add(scoreMacro, "macro_office")
	}
	if hasDoubleExt(a.Filename) {
		add(scoreDoubleExt, "double_ext")
	}

	if score > maxScore {
		score = maxScore
	}
	return Result{Score: score, Reasons: reasons}
}

// fileExt returns the lowercase final extension of name without the dot, or ""
// when there is none.
func fileExt(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// hasDoubleExt reports a disguised double extension — two or more dotted
// segments where the final one is a dangerous/executable type (e.g.
// invoice.pdf.exe, report.doc.scr). Benign multi-dot names like archive.tar.gz
// are not flagged because the final segment is not dangerous.
func hasDoubleExt(name string) bool {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 3 {
		return false
	}
	return dangerousExts[parts[len(parts)-1]]
}

// extMIMEMismatch reports whether a known extension's declared Content-Type is
// inconsistent with it. Unknown extensions or empty content types never count
// as a mismatch.
func extMIMEMismatch(ext, contentType string) bool {
	allowed, known := extMIME[ext]
	if !known {
		return false
	}
	ct := normalizeMIME(contentType)
	if ct == "" {
		return false
	}
	for _, a := range allowed {
		if ct == a {
			return false
		}
	}
	return true
}

// normalizeMIME strips Content-Type parameters and lowercases the media type.
func normalizeMIME(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
