// Attachment analysis: content hashing (SHA256 + MD5 + SHA1), Shannon entropy,
// and magic-byte file-type detection. Per ARCH-SPEC §1 step 2 the parser hashes
// each attachment, computes Shannon entropy, and detects the actual file type
// via magic bytes; SVC-05 later scores from these.
package email

import (
	"crypto/md5"  //nolint:gosec // MD5/SHA1 are content fingerprints for TI hash lookup, not security primitives.
	"crypto/sha1" //nolint:gosec // see above
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strings"
)

// Attachment is one decoded attachment with its derived analysis fields,
// matching the analysis.attachments contract (ARCH-SPEC §1 step 2). Data holds
// the raw decoded bytes so the caller can upload them to object storage (G6).
type Attachment struct {
	Filename     string
	ContentType  string // MIME-declared type
	ContentID    string
	Disposition  string // "inline" | "attachment"
	Data         []byte
	SizeBytes    int64
	SHA256       string
	MD5          string
	SHA1         string
	Entropy      float64
	DetectedType string // magic-byte-derived type (may differ from ContentType)
}

// analyzeAttachment fills the derived fields (hashes, size, entropy, detected
// type) from the raw bytes. The identity fields (filename / content type /
// disposition / content id) are supplied by the MIME walk.
func analyzeAttachment(filename, contentType, contentID, disposition string, data []byte) Attachment {
	sum256 := sha256.Sum256(data)
	sum1 := sha1.Sum(data) //nolint:gosec // fingerprint, not security
	sum5 := md5.Sum(data)  //nolint:gosec // fingerprint, not security
	return Attachment{
		Filename:     filename,
		ContentType:  contentType,
		ContentID:    contentID,
		Disposition:  disposition,
		Data:         data,
		SizeBytes:    int64(len(data)),
		SHA256:       hex.EncodeToString(sum256[:]),
		SHA1:         hex.EncodeToString(sum1[:]),
		MD5:          hex.EncodeToString(sum5[:]),
		Entropy:      ShannonEntropy(data),
		DetectedType: detectContentType(data),
	}
}

// ShannonEntropy returns the byte-level Shannon entropy of data in bits per
// byte, in [0, 8]. High entropy (>7.5) is an SVC-05 packed/encrypted signal.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
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

// magicSignatures maps a leading byte signature to a detected content type for
// the formats SVC-05's extension/MIME-mismatch heuristic cares about. Checked
// before the net/http sniffer so executable/archive/Office types (which
// http.DetectContentType reports only coarsely) are named precisely.
var magicSignatures = []struct {
	prefix []byte
	typ    string
}{
	{[]byte{0x4D, 0x5A}, "application/x-msdownload"},                            // MZ — PE/EXE/DLL
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "application/x-elf"},                       // ELF
	{[]byte{0x25, 0x50, 0x44, 0x46}, "application/pdf"},                         // %PDF
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "application/zip"},                         // PK.. — zip/OOXML/jar
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "application/zip"},                         // empty zip
	{[]byte{0x50, 0x4B, 0x07, 0x08}, "application/zip"},                         // spanned zip
	{[]byte{0xD0, 0xCF, 0x11, 0xE0}, "application/x-ole-storage"},               // legacy Office (doc/xls/ppt)
	{[]byte{0x52, 0x61, 0x72, 0x21}, "application/x-rar-compressed"},            // Rar!
	{[]byte{0x1F, 0x8B}, "application/gzip"},                                    // gzip
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "application/x-7z-compressed"}, // 7z
	{[]byte{0xFF, 0xD8, 0xFF}, "image/jpeg"},
	{[]byte{0x89, 0x50, 0x4E, 0x47}, "image/png"},
	{[]byte{0x47, 0x49, 0x46, 0x38}, "image/gif"},
}

// detectContentType returns the magic-byte-derived content type for data,
// falling back to net/http content sniffing (then "application/octet-stream").
func detectContentType(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	for _, sig := range magicSignatures {
		if len(data) >= len(sig.prefix) && hasPrefixBytes(data, sig.prefix) {
			return sig.typ
		}
	}
	sniffed := http.DetectContentType(data)
	// DetectContentType returns the generic octet-stream when it cannot tell;
	// keep it so SVC-05 still sees a (declared vs detected) comparison input.
	return strings.SplitN(sniffed, ";", 2)[0]
}

func hasPrefixBytes(data, prefix []byte) bool {
	for i := range prefix {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

// detectedTypeToExtension maps a magic-byte-detected content type to the
// canonical file extension stored in attachment_library.actual_extension (no
// leading dot). SVC-05's extension-vs-MIME mismatch heuristic (ARCH-SPEC §3b)
// compares this magic-derived actual extension against the claimed filename
// extension. Returns "" when the type has no single canonical extension.
var detectedTypeToExtension = map[string]string{
	"application/x-msdownload":     "exe",
	"application/x-elf":            "elf",
	"application/pdf":              "pdf",
	"application/zip":              "zip",
	"application/x-ole-storage":    "ole",
	"application/x-rar-compressed": "rar",
	"application/gzip":             "gz",
	"application/x-7z-compressed":  "7z",
	"image/jpeg":                   "jpg",
	"image/png":                    "png",
	"image/gif":                    "gif",
	"text/plain":                   "txt",
	"text/html":                    "html",
}

// ActualExtension returns the magic-byte-derived canonical file extension for
// this attachment (no leading dot), used for attachment_library.actual_extension.
func (a Attachment) ActualExtension() string {
	return detectedTypeToExtension[a.DetectedType]
}
