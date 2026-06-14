package repository

import (
	"testing"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/saif/cybersiren/db/sqlc"
)

// pgText is a tiny helper for building a non-NULL pgtype.Text in tests.
func pgText(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

// Bytes a real Windows-1252 quoted-printable/base64 decode leaves behind that
// Postgres rejects on a UTF-8 column with SQLSTATE 22021. =97 → 0x97 em-dash,
// =a0 → 0xa0 NBSP, =aa → 0xaa, =96 → 0x96 en-dash.
const (
	poison97 = "em\x97dash"
	poisonA0 = "no\xa0break"
	poisonAA = "junk\xaa"
	poison96 = "en\x96dash"
)

// TestValidUTF8 proves the core coercion: invalid byte sequences become valid
// UTF-8 (no 22021) while valid input is passed through untouched.
func TestValidUTF8(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ascii passthrough", "hello world", "hello world"},
		{"valid multibyte passthrough", "café — déjà", "café — déjà"},
		{"empty", "", ""},
		{"0x97 em-dash", poison97, "em" + utf8Replacement + "dash"},
		{"0xa0 nbsp", poisonA0, "no" + utf8Replacement + "break"},
		{"0xaa", poisonAA, "junk" + utf8Replacement},
		{"0x96 en-dash", poison96, "en" + utf8Replacement + "dash"},
		// strings.ToValidUTF8 collapses a contiguous run of invalid bytes into a
		// single replacement — the point is only that the result is valid UTF-8.
		{"all four poison bytes", "\x97\x96\xa0\xaa", utf8Replacement},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := validUTF8(c.in)
			if !utf8.ValidString(got) {
				t.Fatalf("validUTF8(%q) = %q, still not valid UTF-8", c.in, got)
			}
			if got != c.want {
				t.Fatalf("validUTF8(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSanitizeParsedCoercesEveryTextField proves that the single repository
// chokepoint scrubs invalid UTF-8 out of every text/string field on the parent
// email and all three child-row kinds, so no value can reach a UTF-8 column.
func TestSanitizeParsedCoercesEveryTextField(t *testing.T) {
	t.Parallel()
	in := PersistParsedFull{
		MessageID: poison97,
		Email: db.InsertEmailParams{
			MessageID:      pgText(poison97),
			SenderName:     pgText(poison97),
			SenderEmail:    pgText(poisonA0),
			SenderDomain:   pgText(poisonAA),
			ReplyToEmail:   pgText(poison96),
			ReturnPath:     pgText(poison97),
			MailerAgent:    pgText(poisonA0),
			InReplyTo:      pgText(poisonAA),
			ContentCharset: pgText(poison96),
			Precedence:     pgText(poison97),
			ListID:         pgText(poisonA0),
			Subject:        pgText(poisonAA),
			BodyPlain:      pgText(poison97),
			BodyHtml:       pgText(poison96),
			ReferencesList: []string{poison97, poisonA0},
		},
		URLs: []ParsedURL{{
			URL:         poison97,
			Domain:      pgText(poisonA0),
			TLD:         pgText(poisonAA),
			VisibleText: pgText(poison96),
		}},
		Attachments: []ParsedAttachment{{
			Library: db.UpsertParsedAttachmentParams{
				Sha256:          poison97,
				Md5:             pgText(poisonA0),
				Sha1:            pgText(poisonAA),
				ActualExtension: pgText(poison96),
				StorageUri:      pgText(poison97),
			},
			Filename:    pgText(poisonA0),
			ContentType: pgText(poisonAA),
			ContentID:   pgText(poison96),
			Disposition: pgText(poison97),
		}},
		Recipients: []ChildRecipient{{
			Address:       poisonA0,
			DisplayName:   pgText(poisonAA),
			RecipientType: poison96,
		}},
	}

	sanitizeParsed(&in)

	// Walk every string we wrote and assert it is now valid UTF-8.
	check := func(label, s string) {
		t.Helper()
		if !utf8.ValidString(s) {
			t.Errorf("%s still not valid UTF-8 after sanitize: %q", label, s)
		}
	}
	checkText := func(label string, tx pgtype.Text) {
		t.Helper()
		if tx.Valid {
			check(label, tx.String)
		}
	}

	check("out-of-band MessageID", in.MessageID)
	checkText("Email.MessageID", in.Email.MessageID)
	checkText("Email.SenderName", in.Email.SenderName)
	checkText("Email.SenderEmail", in.Email.SenderEmail)
	checkText("Email.SenderDomain", in.Email.SenderDomain)
	checkText("Email.ReplyToEmail", in.Email.ReplyToEmail)
	checkText("Email.ReturnPath", in.Email.ReturnPath)
	checkText("Email.MailerAgent", in.Email.MailerAgent)
	checkText("Email.InReplyTo", in.Email.InReplyTo)
	checkText("Email.ContentCharset", in.Email.ContentCharset)
	checkText("Email.Precedence", in.Email.Precedence)
	checkText("Email.ListID", in.Email.ListID)
	checkText("Email.Subject", in.Email.Subject)
	checkText("Email.BodyPlain", in.Email.BodyPlain)
	checkText("Email.BodyHtml", in.Email.BodyHtml)
	for i, r := range in.Email.ReferencesList {
		check("Email.ReferencesList", r)
		_ = i
	}

	check("URLs[0].URL", in.URLs[0].URL)
	checkText("URLs[0].Domain", in.URLs[0].Domain)
	checkText("URLs[0].TLD", in.URLs[0].TLD)
	checkText("URLs[0].VisibleText", in.URLs[0].VisibleText)

	check("Attachments[0].Library.Sha256", in.Attachments[0].Library.Sha256)
	checkText("Attachments[0].Library.Md5", in.Attachments[0].Library.Md5)
	checkText("Attachments[0].Library.Sha1", in.Attachments[0].Library.Sha1)
	checkText("Attachments[0].Library.ActualExtension", in.Attachments[0].Library.ActualExtension)
	checkText("Attachments[0].Library.StorageUri", in.Attachments[0].Library.StorageUri)
	checkText("Attachments[0].Filename", in.Attachments[0].Filename)
	checkText("Attachments[0].ContentType", in.Attachments[0].ContentType)
	checkText("Attachments[0].ContentID", in.Attachments[0].ContentID)
	checkText("Attachments[0].Disposition", in.Attachments[0].Disposition)

	check("Recipients[0].Address", in.Recipients[0].Address)
	checkText("Recipients[0].DisplayName", in.Recipients[0].DisplayName)
	check("Recipients[0].RecipientType", in.Recipients[0].RecipientType)
}

// TestSanitizeParsedPreservesValidContent makes sure we only rewrite invalid
// bytes — valid (incl. multibyte) content survives unchanged, so the fix never
// silently drops legitimate text.
func TestSanitizeParsedPreservesValidContent(t *testing.T) {
	t.Parallel()
	const subj = "Re: café déjà vu — 你好"
	in := PersistParsedFull{Email: db.InsertEmailParams{Subject: pgText(subj)}}
	sanitizeParsed(&in)
	if in.Email.Subject.String != subj {
		t.Fatalf("valid subject mutated: got %q want %q", in.Email.Subject.String, subj)
	}
}

// TestSanitizeParsedSentTimestamp proves an out-of-range or garbage Date header
// is nulled (rather than passed through to violate chk_emails_sent_timestamp_range,
// SQLSTATE 23514), while an in-range value — including the boundary values and
// epoch-zero — is preserved.
func TestSanitizeParsedSentTimestamp(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        pgtype.Int8
		wantValid bool
		wantVal   int64
	}{
		{"null stays null", pgtype.Int8{}, false, 0},
		{"epoch zero preserved", pgtype.Int8{Int64: 0, Valid: true}, true, 0},
		{"in range preserved", pgtype.Int8{Int64: 1_700_000_000, Valid: true}, true, 1_700_000_000},
		{"lower bound preserved", pgtype.Int8{Int64: sentTimestampMin, Valid: true}, true, sentTimestampMin},
		{"upper bound preserved", pgtype.Int8{Int64: sentTimestampMax, Valid: true}, true, sentTimestampMax},
		{"negative nulled", pgtype.Int8{Int64: -1, Valid: true}, false, 0},
		{"far future nulled", pgtype.Int8{Int64: sentTimestampMax + 1, Valid: true}, false, 0},
		{"garbage huge nulled", pgtype.Int8{Int64: 99_999_999_999, Valid: true}, false, 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := PersistParsedFull{Email: db.InsertEmailParams{SentTimestamp: c.in}}
			sanitizeParsed(&in)
			got := in.Email.SentTimestamp
			if got.Valid != c.wantValid {
				t.Fatalf("Valid = %v, want %v", got.Valid, c.wantValid)
			}
			if got.Valid && got.Int64 != c.wantVal {
				t.Fatalf("Int64 = %d, want %d", got.Int64, c.wantVal)
			}
		})
	}
}
