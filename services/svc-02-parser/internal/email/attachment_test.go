package email

import (
	"crypto/md5"  //nolint:gosec // test asserts the fingerprint values
	"crypto/sha1" //nolint:gosec // test asserts the fingerprint values
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"
)

func TestAnalyzeAttachmentHashes(t *testing.T) {
	data := []byte("the quick brown fox")
	att := analyzeAttachment("doc.txt", "text/plain", "cid-1", "attachment", data)

	wantSHA256 := sha256.Sum256(data)
	want1 := sha1.Sum(data) //nolint:gosec
	want5 := md5.Sum(data)  //nolint:gosec
	if att.SHA256 != hex.EncodeToString(wantSHA256[:]) {
		t.Errorf("sha256 = %s, want %s", att.SHA256, hex.EncodeToString(wantSHA256[:]))
	}
	if att.SHA1 != hex.EncodeToString(want1[:]) {
		t.Errorf("sha1 = %s, want %s", att.SHA1, hex.EncodeToString(want1[:]))
	}
	if att.MD5 != hex.EncodeToString(want5[:]) {
		t.Errorf("md5 = %s, want %s", att.MD5, hex.EncodeToString(want5[:]))
	}
	if att.SizeBytes != int64(len(data)) {
		t.Errorf("size = %d, want %d", att.SizeBytes, len(data))
	}
	if att.Disposition != "attachment" {
		t.Errorf("disposition = %q, want attachment", att.Disposition)
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := ShannonEntropy(nil); e != 0 {
		t.Errorf("entropy(nil) = %f, want 0", e)
	}
	// A single repeated byte has zero entropy.
	if e := ShannonEntropy([]byte{0x41, 0x41, 0x41, 0x41}); e != 0 {
		t.Errorf("entropy(constant) = %f, want 0", e)
	}
	// All 256 byte values once each → maximal 8 bits/byte.
	full := make([]byte, 256)
	for i := range full {
		full[i] = byte(i)
	}
	if e := ShannonEntropy(full); math.Abs(e-8.0) > 1e-9 {
		t.Errorf("entropy(uniform) = %f, want 8", e)
	}
}

func TestDetectContentTypeMagicBytes(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"PE exe", []byte{0x4D, 0x5A, 0x90, 0x00}, "application/x-msdownload"},
		{"PDF", []byte("%PDF-1.7\n..."), "application/pdf"},
		{"ZIP/OOXML", []byte{0x50, 0x4B, 0x03, 0x04, 0x14}, "application/zip"},
		{"legacy office", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1}, "application/x-ole-storage"},
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D}, "image/png"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectContentType(tt.data); got != tt.want {
				t.Errorf("detectContentType() = %q, want %q", got, tt.want)
			}
		})
	}
	if got := detectContentType(nil); got != "" {
		t.Errorf("detectContentType(nil) = %q, want empty", got)
	}
}
