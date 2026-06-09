// Package email is SVC-02's real RFC 822 / MIME parser. It walks the multipart
// tree, extracts headers (sender identity + auth results), the HTML and plain-
// text bodies, every URL (with per-URL context), every attachment (hashed +
// entropy + magic-byte type), and the recipient list, then derives the content
// plan (url_count / attachment_count / has_body). See ARCH-SPEC §1 step 2 and
// §14 step 2.
//
// D9: the parser ships the body content (raw HTML + sanitized plain text) so
// SVC-04 can compute the structural signals it owns — the parser does NOT
// compute html_only / has_hidden_text / has_form / encoding flags.
package email

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	encbase64 "encoding/base64"
)

// maxParts bounds the MIME walk so a maliciously deep/nested message cannot
// exhaust memory or CPU during parse.
const maxParts = 200

// Recipient is one to/cc/bcc address parsed from the headers.
type Recipient struct {
	Address     string
	DisplayName string
	Type        string // "to" | "cc" | "bcc"
}

// ParsedEmail is the structured result of parsing one raw RFC 822 message. It
// is the parser's internal model; the SVC-02 handler maps it onto the DB write
// params and the analysis.* wire contracts.
type ParsedEmail struct {
	// Header is the canonicalized header map (last value wins) used for header
	// projection onto analysis.headers / emails.
	Header mail.Header

	Subject   string
	BodyHTML  string // raw HTML body part ("" when none)
	BodyPlain string // HTML-stripped clean plain text (NLP body)

	URLs        []ExtractedURL
	Attachments []Attachment
	Recipients  []Recipient

	// htmlBuf / plainBuf accumulate body parts during the MIME walk so repeated
	// concatenation stays linear; finalize() stringifies them into BodyHTML /
	// BodyPlain once the walk is done.
	htmlBuf  strings.Builder
	plainBuf strings.Builder
}

// HasBody reports whether the parsed email carries any body content (HTML or
// plain), used for analysis.plans.has_body.
func (p *ParsedEmail) HasBody() bool {
	return strings.TrimSpace(p.BodyPlain) != "" || strings.TrimSpace(p.BodyHTML) != ""
}

// Parse decodes a full RFC 822 message (raw bytes, already base64-decoded off
// the wire) into a ParsedEmail. A nil error with empty bodies/URLs is a valid
// result for a header-only message; Parse only errors when the top-level
// headers cannot be read at all.
func Parse(raw []byte) (*ParsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("read rfc822 message: %w", err)
	}

	pe := &ParsedEmail{Header: msg.Header}
	pe.Subject = decodeHeader(msg.Header.Get("Subject"))
	pe.Recipients = parseRecipients(msg.Header)

	mediaType, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mediaType == "" {
		// RFC 2045 §5.2: a message with no/invalid Content-Type defaults to
		// text/plain; us-ascii. Without this a bodied non-MIME message would be
		// mis-routed as a binary attachment.
		mediaType = "text/plain"
	}
	count := 0
	walkPart(mediaType, params, msg.Header.Get("Content-Transfer-Encoding"),
		msg.Header.Get("Content-Disposition"), msg.Header.Get("Content-ID"), msg.Body, pe, &count)

	pe.finalize()
	return pe, nil
}

// finalize stringifies the accumulated body buffers, derives the plain-text
// body from HTML when only HTML was present, and dedupes the URL list.
func (p *ParsedEmail) finalize() {
	p.BodyHTML = p.htmlBuf.String()
	p.BodyPlain = p.plainBuf.String()
	if strings.TrimSpace(p.BodyPlain) == "" && p.BodyHTML != "" {
		p.BodyPlain = HTMLToText(p.BodyHTML)
	}
	if p.BodyHTML != "" {
		p.URLs = append(p.URLs, ExtractURLsFromHTML(p.BodyHTML)...)
	}
	if p.BodyPlain != "" {
		p.URLs = append(p.URLs, ExtractURLsFromText(p.BodyPlain)...)
	}
	p.URLs = DedupeURLs(p.URLs)
}

// walkPart recursively descends the MIME tree. For multipart/* it splits on the
// boundary and recurses; for leaf parts it routes to a body or an attachment.
func walkPart(mediaType string, params map[string]string, cte, disposition, contentID string, body io.Reader, pe *ParsedEmail, count *int) {
	if *count > maxParts {
		return
	}
	*count++

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			ptType, ptParams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if ptType == "" {
				ptType = "text/plain"
			}
			walkPart(ptType, ptParams, part.Header.Get("Content-Transfer-Encoding"),
				part.Header.Get("Content-Disposition"), part.Header.Get("Content-ID"), part, pe, count)
			_ = part.Close()
		}
	}

	decoded := decodeBody(body, cte)

	disp, dispParams := parseDisposition(disposition)
	filename := dispParams["filename"]
	if filename == "" {
		filename = params["name"]
	}

	// An explicit attachment/inline disposition with a filename, or any non-text
	// leaf, is treated as an attachment. text/* with no filename is body content.
	isText := strings.HasPrefix(mediaType, "text/")
	if (disp == "attachment" || disp == "inline" || filename != "") && !(isText && filename == "") {
		pe.Attachments = append(pe.Attachments, analyzeAttachment(
			decodeHeader(filename), mediaType, strings.Trim(contentID, "<>"), normalizeDisposition(disp), decoded))
		return
	}

	switch {
	case mediaType == "text/html":
		pe.htmlBuf.Write(decoded)
	case mediaType == "text/plain", isText:
		pe.plainBuf.Write(decoded)
	default:
		// Unknown non-text leaf with no disposition: keep as an attachment so
		// nothing is silently dropped.
		pe.Attachments = append(pe.Attachments, analyzeAttachment(
			decodeHeader(filename), mediaType, strings.Trim(contentID, "<>"), normalizeDisposition(disp), decoded))
	}
}

// decodeBody applies the Content-Transfer-Encoding (base64 / quoted-printable)
// to a part body, returning the raw decoded bytes. Unknown/7bit/8bit/binary
// encodings pass through unchanged.
func decodeBody(r io.Reader, cte string) []byte {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		raw, _ := io.ReadAll(r)
		// Tolerate embedded whitespace/newlines common in MIME base64.
		clean := stripWhitespaceBytes(raw)
		dst := make([]byte, encbase64.StdEncoding.DecodedLen(len(clean)))
		n, err := encbase64.StdEncoding.Decode(dst, clean)
		if err != nil {
			// Fall back to raw on malformed base64 so the part is not lost.
			return raw
		}
		return dst[:n]
	case "quoted-printable":
		// On a malformed QP stream io.ReadAll returns the bytes decoded so far;
		// keep those partial bytes intentionally rather than losing the part.
		out, _ := io.ReadAll(quotedprintable.NewReader(r))
		return out
	default:
		raw, _ := io.ReadAll(r)
		return raw
	}
}

func stripWhitespaceBytes(b []byte) []byte {
	// Build into a fresh slice — never mutate b's backing array, so the base64
	// error path in decodeBody can hand back the original raw bytes intact.
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case '\n', '\r', '\t', ' ':
			continue
		default:
			out = append(out, c)
		}
	}
	return out
}

// parseRecipients pulls To / Cc / Bcc into a flat recipient list.
func parseRecipients(h mail.Header) []Recipient {
	var out []Recipient
	for _, hdr := range []struct{ name, typ string }{
		{"To", "to"}, {"Cc", "cc"}, {"Bcc", "bcc"},
	} {
		addrs, err := h.AddressList(hdr.name)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a == nil || a.Address == "" {
				continue
			}
			out = append(out, Recipient{
				Address:     a.Address,
				DisplayName: a.Name,
				Type:        hdr.typ,
			})
		}
	}
	return out
}

func parseDisposition(raw string) (string, map[string]string) {
	if strings.TrimSpace(raw) == "" {
		return "", map[string]string{}
	}
	disp, params, err := mime.ParseMediaType(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw)), map[string]string{}
	}
	return strings.ToLower(disp), params
}

// normalizeDisposition maps the parsed disposition onto the contract's
// "inline" | "attachment" values, defaulting to "attachment".
func normalizeDisposition(disp string) string {
	if disp == "inline" {
		return "inline"
	}
	return "attachment"
}

// ParseAuthResults parses the common single-line Authentication-Results shape:
//
//	"spf=pass smtp.mailfrom=…; dkim=fail; dmarc=fail; arc=none"
//
// returning a map of mechanism → result for spf/dkim/dmarc/arc. It does NOT
// implement the full RFC 8601 grammar — it extracts the leading method=result
// token of each segment, which covers the providers SVC-04 scores against.
func ParseAuthResults(raw string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		lower := strings.ToLower(segment)
		for _, mech := range []string{"spf", "dkim", "dmarc", "arc"} {
			prefix := mech + "="
			i := strings.Index(lower, prefix)
			if i < 0 {
				continue
			}
			// Require the match to start at a token boundary so "dkim" does not
			// swallow a trailing "x-dkim=" or a value mentioning the word.
			if i > 0 && !isAuthBoundary(lower[i-1]) {
				continue
			}
			value := segment[i+len(prefix):]
			value = strings.SplitN(strings.TrimSpace(value), " ", 2)[0]
			value = strings.TrimRight(value, ";")
			if value != "" && out[mech] == "" {
				out[mech] = strings.ToLower(value)
			}
		}
	}
	return out
}

func isAuthBoundary(c byte) bool {
	switch c {
	case ' ', '\t', ';', ',':
		return true
	}
	return false
}

// decodeHeader decodes RFC 2047 encoded-words ("=?utf-8?B?…?=") in a header
// value, returning the original on any decode failure.
func decodeHeader(v string) string {
	if v == "" {
		return ""
	}
	dec := new(mime.WordDecoder)
	out, err := dec.DecodeHeader(v)
	if err != nil {
		return v
	}
	return out
}
