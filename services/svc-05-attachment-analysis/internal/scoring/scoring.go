// Package scoring holds SVC-05's pure attachment-scoring logic: the five
// heuristics from ARCH-SPEC §1 step 3c, the per-attachment score combiner, and
// the per-email max. Nothing here talks to Postgres, Kafka, or VirusTotal — it
// is deterministic over the (Attachment, Config) inputs so it is exhaustively
// unit-testable without infrastructure (G4: heuristics only, no NER / retrain).
package scoring

import (
	"math"
	"path"
	"strings"
)

// Config carries the tunable score impacts and the entropy threshold. It is a
// projection of shared/config.AttachmentConfig so this package has no
// dependency on the config loader.
type Config struct {
	EntropyThreshold       float64
	HighEntropyScore       int
	ExtensionMismatchScore int
	DangerousExtScore      int
	MacroOfficeScore       int
	DoubleExtScore         int
	MaliciousHashScore     int
}

// Attachment is the per-attachment input the scorer reads. It mirrors the
// fields SVC-05 needs from the analysis.attachments contract plus the
// attachment_library hash-lookup verdict.
type Attachment struct {
	SHA256       string
	Filename     string
	ContentType  string // MIME type declared by the email
	DetectedType string // magic-byte-derived type (may be empty)
	SizeBytes    int64
	Entropy      float64

	// HashIsMalicious is the attachment_library.is_malicious verdict for this
	// sha256 (false when the hash is unknown). When true the per-attachment
	// score is forced to MaliciousHashScore.
	HashIsMalicious bool

	// VTMalicious is true when the VirusTotal cache/API reported
	// malicious_votes > 0 for this hash. Treated like a hash hit.
	VTMalicious bool
}

// Heuristics is the boolean trail of which signals fired, surfaced on the
// per-attachment AttachmentDetail for explainability.
type Heuristics struct {
	HighEntropy          bool
	ExtensionMismatch    bool
	IsDangerousExtension bool
	HasMacros            bool
	DoubleExtension      bool
}

// Result is the scored output for one attachment.
type Result struct {
	Score      int
	Heuristics Heuristics
	// Malicious is true when the hash verdict (library or VT) flagged the
	// attachment, independent of the heuristic trail.
	Malicious bool
}

// dangerousExtensions are executable / script extensions that warrant a high
// individual score on their own (ARCH-SPEC §1 step 3c "dangerous ext").
var dangerousExtensions = map[string]struct{}{
	".exe": {}, ".scr": {}, ".bat": {}, ".cmd": {}, ".com": {}, ".pif": {},
	".vbs": {}, ".vbe": {}, ".js": {}, ".jse": {}, ".wsf": {}, ".wsh": {},
	".ps1": {}, ".msi": {}, ".jar": {}, ".cpl": {}, ".hta": {}, ".lnk": {},
	".reg": {}, ".dll": {}, ".sys": {}, ".scf": {}, ".gadget": {}, ".msc": {},
	".ws": {}, ".msp": {}, ".inf": {}, ".sh": {}, ".run": {},
}

// macroOfficeExtensions are macro-enabled Office document extensions
// (ARCH-SPEC §1 step 3c "macro Office").
var macroOfficeExtensions = map[string]struct{}{
	".docm": {}, ".dotm": {}, ".xlsm": {}, ".xltm": {}, ".xlam": {},
	".pptm": {}, ".potm": {}, ".ppam": {}, ".ppsm": {}, ".sldm": {},
}

// archiveExtensions are containers whose declared MIME legitimately differs from
// a magic-byte detector reporting the inner/compressed type; excluded from the
// extension-mismatch heuristic to cut false positives.
var archiveExtensions = map[string]struct{}{
	".zip": {}, ".gz": {}, ".tgz": {}, ".bz2": {}, ".7z": {}, ".rar": {},
	".tar": {}, ".xz": {},
}

// oleContainer is the magic-byte-derived type SVC-02 reports for legacy
// OLE-Compound-Document Office files (.doc/.xls/.ppt). The format is a generic
// container, so a byte sniffer cannot distinguish Word from Excel; the declared
// MIME carries the specific type and the detected type is this coarse one.
const oleContainer = "application/x-ole-storage"

// zipContainer is the magic-byte-derived type SVC-02 reports for OOXML Office
// files (.docx/.xlsx/.pptx) — they are ZIP archives on disk — and for plain
// .zip. Like oleContainer it is a coarse container type that legitimately
// differs from the specific declared MIME.
const zipContainer = "application/zip"

// mimeExtensionMap maps a small set of common extensions to the MIME-type
// prefix (or exact type) the declared content_type SHOULD carry. Only used to
// flag clear mismatches (e.g. a ".pdf" declared as image/png); unknown
// extensions are skipped rather than guessed.
//
// Each list also includes the COARSE magic-container type SVC-02's byte sniffer
// actually reports for that family (zipContainer for OOXML/.zip, oleContainer
// for legacy Office, text/plain for text-family formats). The sniffer cannot
// see past the container/charset to the specific subtype, so without these the
// detected-type branch would fire extension_mismatch on every legitimate
// .docx/.xls/.json (the false positive this map closes). A genuine swap —
// e.g. a .pdf whose bytes are image/png or that declares x-msdownload — still
// has neither the specific nor the coarse type in its list, so it still fires.
var mimeExtensionMap = map[string][]string{
	".pdf":  {"application/pdf"},
	".png":  {"image/png"},
	".jpg":  {"image/jpeg"},
	".jpeg": {"image/jpeg"},
	".gif":  {"image/gif"},
	".bmp":  {"image/bmp"},
	".webp": {"image/webp"},
	".txt":  {"text/plain"},
	".html": {"text/html", "text/plain"},
	".htm":  {"text/html", "text/plain"},
	".csv":  {"text/csv", "application/csv", "text/plain"},
	".xml":  {"text/xml", "application/xml", "text/plain"},
	".json": {"application/json", "text/plain"},
	".doc":  {"application/msword", oleContainer},
	".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", zipContainer},
	".xls":  {"application/vnd.ms-excel", oleContainer},
	".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", zipContainer},
	".ppt":  {"application/vnd.ms-powerpoint", oleContainer},
	".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", zipContainer},
	".zip":  {"application/zip", "application/x-zip-compressed"},
	".exe": {
		"application/x-msdownload", "application/octet-stream",
		"application/x-dosexec", "application/vnd.microsoft.portable-executable",
	},
}

// Score computes the per-attachment risk score and heuristic trail. A hash hit
// (attachment_library.is_malicious or a VT malicious verdict) short-circuits to
// MaliciousHashScore — the strongest signal — while still reporting which
// heuristics fired for the detail trail. Otherwise the score is the sum of the
// fired heuristic impacts, clamped to [0, 100].
func Score(a Attachment, cfg Config) Result {
	h := Heuristics{
		HighEntropy:          a.Entropy > cfg.EntropyThreshold,
		ExtensionMismatch:    extensionMismatch(a.Filename, a.ContentType, a.DetectedType),
		IsDangerousExtension: isDangerousExtension(a.Filename),
		HasMacros:            isMacroOffice(a.Filename),
		DoubleExtension:      hasDoubleExtension(a.Filename),
	}

	malicious := a.HashIsMalicious || a.VTMalicious

	var score int
	if malicious {
		score = cfg.MaliciousHashScore
	} else {
		if h.HighEntropy {
			score += cfg.HighEntropyScore
		}
		if h.ExtensionMismatch {
			score += cfg.ExtensionMismatchScore
		}
		if h.IsDangerousExtension {
			score += cfg.DangerousExtScore
		}
		if h.HasMacros {
			score += cfg.MacroOfficeScore
		}
		if h.DoubleExtension {
			score += cfg.DoubleExtScore
		}
	}

	return Result{
		Score:      clamp(score, 0, 100),
		Heuristics: h,
		Malicious:  malicious,
	}
}

// ShannonEntropy returns the Shannon entropy (bits per byte, 0..8) of b. The
// parser already ships per-attachment entropy on the contract, but SVC-05
// recomputes it locally when it has the bytes (and exposes this helper for the
// heuristic + tests).
func ShannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// extensionMismatch flags a declared MIME that contradicts the filename
// extension. It is intentionally conservative: it only fires when the extension
// is in mimeExtensionMap AND the declared content_type is non-empty AND does not
// match any expected MIME for that extension. Archives are skipped (a detector
// legitimately reports the compressed payload type). detectedType, when present
// and disagreeing with the declared type for a mapped extension, also fires.
func extensionMismatch(filename, contentType, detectedType string) bool {
	ext := extOf(filename)
	if ext == "" {
		return false
	}
	if _, isArchive := archiveExtensions[ext]; isArchive {
		return false
	}
	expected, known := mimeExtensionMap[ext]
	if !known {
		return false
	}

	declared := normalizeMIME(contentType)
	if declared != "" && declared != "application/octet-stream" && !matchesAny(declared, expected) {
		return true
	}

	detected := normalizeMIME(detectedType)
	if detected != "" && detected != "application/octet-stream" && !matchesAny(detected, expected) {
		return true
	}
	return false
}

func matchesAny(mime string, expected []string) bool {
	for _, e := range expected {
		if mime == e {
			return true
		}
	}
	return false
}

// normalizeMIME lowercases and strips any "; charset=..." parameters from a MIME
// type so comparison is on the bare type/subtype.
func normalizeMIME(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// trailingExtNoise is the set of trailing characters Windows ignores when it
// resolves/executes a filename, so "invoice.exe." and "invoice.exe " both run as
// "invoice.exe". Stripping them before taking the extension stops a one-character
// filename trick from defeating every extension heuristic (path.Ext("invoice.exe.")
// == "." and path.Ext("invoice.exe ") == ".exe " — neither is in any ext set).
const trailingExtNoise = ". \t\r\n\f\v"

// extOf returns the lower-cased file extension of name after trimming Windows-
// ignored trailing dots/whitespace.
func extOf(name string) string {
	return strings.ToLower(path.Ext(strings.TrimRight(name, trailingExtNoise)))
}

func isDangerousExtension(filename string) bool {
	_, ok := dangerousExtensions[extOf(filename)]
	return ok
}

func isMacroOffice(filename string) bool {
	_, ok := macroOfficeExtensions[extOf(filename)]
	return ok
}

// hasDoubleExtension flags filenames with two extensions where the LAST one is
// dangerous and a benign-looking extension precedes it (e.g. "invoice.pdf.exe").
// A plain "archive.tar.gz" does not fire because .gz is not dangerous.
func hasDoubleExtension(filename string) bool {
	base := path.Base(strings.ToLower(strings.TrimRight(filename, trailingExtNoise)))
	lastExt := path.Ext(base)
	if lastExt == "" {
		return false
	}
	if _, dangerous := dangerousExtensions[lastExt]; !dangerous {
		return false
	}
	stem := strings.TrimSuffix(base, lastExt)
	priorExt := path.Ext(stem)
	if priorExt == "" {
		return false
	}
	// The prior segment must look like a real extension (1–5 alnum chars) so we
	// don't fire on hostnames or version dots like "report.v2.exe" being
	// over-counted — though even those are suspicious, we keep it to recognised
	// document/media extensions to avoid noise.
	if _, priorDangerous := dangerousExtensions[priorExt]; priorDangerous {
		// e.g. ".bat.exe" — still a double-extension lure.
		return true
	}
	if _, mapped := mimeExtensionMap[priorExt]; mapped {
		return true
	}
	if _, macro := macroOfficeExtensions[priorExt]; macro {
		return true
	}
	return false
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
