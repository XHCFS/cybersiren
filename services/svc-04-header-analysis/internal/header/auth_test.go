package header

import (
	"testing"

	contractsk "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestNormalizeAuthResult(t *testing.T) {
	t.Parallel()

	cases := map[string]AuthResult{
		"":             AuthResultMissing,
		"  ":           AuthResultMissing,
		"PASS":         AuthResultPass,
		" pass ":       AuthResultPass,
		"fail":         AuthResultFail,
		"PermError":    AuthResultFail,
		"perm-error":   AuthResultFail,
		"softfail":     AuthResultSoftfail,
		"SOFT-FAIL":    AuthResultSoftfail,
		"none":         AuthResultNone,
		"neutral":      AuthResultNone,
		"temperror":    AuthResultNone,
		"unrecognised": AuthResultNone,
	}
	for in, want := range cases {
		got := normalizeAuthResult(in)
		if got != want {
			t.Errorf("normalizeAuthResult(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractAuth_AllNone(t *testing.T) {
	t.Parallel()

	got := ExtractAuth(&contractsk.AnalysisHeadersMessage{})
	if got.SPF != AuthResultMissing || got.DKIM != AuthResultMissing ||
		got.DMARC != AuthResultMissing || got.ARC != AuthResultMissing {
		t.Errorf("expected all-missing, got %+v", got)
	}
	if got.FromReplyToMatch || got.FromReturnPathMatch {
		t.Errorf("alignment must be false when no addresses present, got %+v", got)
	}
}

func TestExtractAuth_AlignmentMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		from              string
		replyTo           string
		returnPath        string
		wantReplyToMatch  bool
		wantReturnMatch   bool
		wantHasReplyTo    bool
		wantHasReturnPath bool
	}{
		{
			name:              "exact match across all three",
			from:              "alice@example.com",
			replyTo:           "alice@example.com",
			returnPath:        "<bounce@example.com>",
			wantReplyToMatch:  true,
			wantReturnMatch:   true,
			wantHasReplyTo:    true,
			wantHasReturnPath: true,
		},
		{
			name:             "subdomain Reply-To still aligned",
			from:             "alice@example.com",
			replyTo:          "alice@mail.example.com",
			wantReplyToMatch: true,
			wantHasReplyTo:   true,
		},
		{
			name:             "mixed case and trailing dot align",
			from:             "alice@Example.COM.",
			replyTo:          "bob@example.com",
			wantReplyToMatch: true,
			wantHasReplyTo:   true,
		},
		{
			name:             "Reply-To on different brand → mismatch",
			from:             "billing@bank.com",
			replyTo:          "billing@bank-secure.com",
			wantReplyToMatch: false,
			wantHasReplyTo:   true,
		},
		{
			name:              "Return-Path bare domain mismatch",
			from:              "alice@example.com",
			returnPath:        "evil.com",
			wantReturnMatch:   false,
			wantHasReturnPath: true,
		},
		{
			name:             "single label suffix is not enough",
			from:             "user@a.b",
			replyTo:          "user@x.b",
			wantReplyToMatch: false,
			wantHasReplyTo:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractAuth(&contractsk.AnalysisHeadersMessage{
				SenderEmail:  tc.from,
				ReplyToEmail: tc.replyTo,
				ReturnPath:   tc.returnPath,
			})
			if got.FromReplyToMatch != tc.wantReplyToMatch {
				t.Errorf("FromReplyToMatch = %v, want %v", got.FromReplyToMatch, tc.wantReplyToMatch)
			}
			if got.FromReturnPathMatch != tc.wantReturnMatch {
				t.Errorf("FromReturnPathMatch = %v, want %v", got.FromReturnPathMatch, tc.wantReturnMatch)
			}
			if got.HasReplyTo != tc.wantHasReplyTo {
				t.Errorf("HasReplyTo = %v, want %v", got.HasReplyTo, tc.wantHasReplyTo)
			}
			if got.HasReturnPath != tc.wantHasReturnPath {
				t.Errorf("HasReturnPath = %v, want %v", got.HasReturnPath, tc.wantHasReturnPath)
			}
		})
	}
}

func TestDomainOf(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":                              "",
		"alice@example.com":             "example.com",
		"  alice@Example.COM ":          "example.com",
		"<alice@example.com>":           "example.com",
		"\"Alice\" <alice@example.com>": "example.com",
		"alice":                         "alice",
		"example.com":                   "example.com",
	}
	for in, want := range cases {
		got := domainOf(in)
		if got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractAuth_NilMessage(t *testing.T) {
	t.Parallel()

	got := ExtractAuth(nil)
	zero := AuthSignals{}
	if got != zero {
		t.Errorf("ExtractAuth(nil) = %+v, want zero value", got)
	}
}
