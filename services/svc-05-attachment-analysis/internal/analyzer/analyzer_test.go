package analyzer

import (
	"reflect"
	"sort"
	"testing"
)

func TestScoreMaliciousShortCircuits(t *testing.T) {
	t.Parallel()
	// A malicious hash scores 90 regardless of other (clean) attributes.
	r := Score(Attachment{Filename: "x.pdf", ContentType: "application/pdf", IsMalicious: true})
	if r.Score != 90 {
		t.Fatalf("malicious score = %d, want 90", r.Score)
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "malicious_hash" {
		t.Fatalf("reasons = %v, want [malicious_hash]", r.Reasons)
	}
}

func TestScoreHeuristicPointValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   Attachment
		want int
		why  []string
	}{
		{"clean pdf", Attachment{Filename: "invoice.pdf", ContentType: "application/pdf", Entropy: 4.0}, 0, nil},
		{"high entropy only", Attachment{Filename: "data.bin", ContentType: "application/octet-stream", Entropy: 7.6}, 20, []string{"high_entropy"}},
		{"entropy boundary not >7.5", Attachment{Filename: "data.bin", ContentType: "application/octet-stream", Entropy: 7.5}, 0, nil},
		{"dangerous ext", Attachment{Filename: "setup.exe", ContentType: "application/octet-stream", Entropy: 1}, 25, []string{"dangerous_ext"}},
		{"macro office", Attachment{Filename: "report.docm", ContentType: "application/vnd.ms-word.document.macroEnabled.12", Entropy: 1}, 20, []string{"macro_office"}},
		{"ext mime mismatch", Attachment{Filename: "photo.pdf", ContentType: "image/png", Entropy: 1}, 30, []string{"ext_mime_mismatch"}},
		{"double ext pdf.exe", Attachment{Filename: "invoice.pdf.exe", ContentType: "application/octet-stream", Entropy: 1}, 25 + 35, []string{"dangerous_ext", "double_ext"}},
		{"double ext doc.scr", Attachment{Filename: "report.doc.scr", ContentType: "application/octet-stream", Entropy: 1}, 25 + 35, []string{"dangerous_ext", "double_ext"}},
		{"tar.gz not double ext", Attachment{Filename: "archive.tar.gz", ContentType: "application/gzip", Entropy: 1}, 0, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := Score(tc.in)
			if r.Score != tc.want {
				t.Errorf("score = %d, want %d (reasons %v)", r.Score, tc.want, r.Reasons)
			}
			got := append([]string(nil), r.Reasons...)
			sort.Strings(got)
			want := append([]string(nil), tc.why...)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("reasons = %v, want %v", got, want)
			}
		})
	}
}

func TestScoreStacksAdditively(t *testing.T) {
	t.Parallel()
	// Worst realistic non-malicious stack: a disguised executable with high
	// entropy → dangerous(25)+double(35)+entropy(20) = 80. The heuristics are
	// mutually exclusive on the final extension (mismatch/macro need a known
	// non-dangerous ext), so 80 is the practical ceiling; the 100 cap guards
	// against future rule additions.
	r := Score(Attachment{Filename: "invoice.pdf.exe", ContentType: "application/octet-stream", Entropy: 7.9})
	if r.Score != 80 {
		t.Fatalf("score = %d, want 80 (dangerous+double+entropy)", r.Score)
	}
	if r.Score > maxScore {
		t.Fatalf("score %d exceeds cap %d", r.Score, maxScore)
	}
}

func TestExtMIMEMismatchUnknownExtIsClean(t *testing.T) {
	t.Parallel()
	// Unknown extension → no mismatch even with an odd content type.
	if extMIMEMismatch("xyz", "application/pdf") {
		t.Error("unknown extension must not count as a mismatch")
	}
	// Empty content type → no mismatch.
	if extMIMEMismatch("pdf", "") {
		t.Error("empty content type must not count as a mismatch")
	}
	// Param-laden but matching type → no mismatch.
	if extMIMEMismatch("pdf", "application/pdf; charset=binary") {
		t.Error("matching type with params must not count as a mismatch")
	}
}

func TestFileExt(t *testing.T) {
	t.Parallel()
	cases := map[string]string{"a.PDF": "pdf", "a.tar.gz": "gz", "noext": "", "trailing.": ""}
	for in, want := range cases {
		if got := fileExt(in); got != want {
			t.Errorf("fileExt(%q) = %q, want %q", in, got, want)
		}
	}
}
