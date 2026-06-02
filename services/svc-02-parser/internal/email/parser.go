// Package email parses raw RFC-822 messages into the structured shape the
// parser service persists and fans out: decoded bodies, hashed attachments,
// extracted URLs, and recipients. It walks nested multipart trees, decodes
// content-transfer-encoding, and is deliberately best-effort — a malformed
// part is skipped rather than failing the whole message.
package email

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // MD5/SHA1 are retained for IOC matching, not security.
	"crypto/sha1" //nolint:gosec // MD5/SHA1 are retained for IOC matching, not security.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// maxPartBytes caps how much of a single MIME part we buffer in memory. It
// guards against decompression-bomb style payloads while staying well above
// any realistic email attachment.
const maxPartBytes = 32 << 20 // 32 MiB

// urlRE matches http(s) URLs in plain text. RE2 forbids unbounded backtracking
// so we match greedily then trim trailing punctuation in dedupeURLs.
var urlRE = regexp.MustCompile(`https?://[^\s<>"')]+`)

// ParsedEmail is the structured result of parsing one RFC-822 message.
type ParsedEmail struct {
	Headers     map[string]string
	Subject     string
	BodyPlain   string
	BodyHTML    string
	URLs        []ExtractedURL
	Attachments []ParsedAttachment
	Recipients  []Recipient
}

// ExtractedURL is a single URL found in the email body. VisibleText carries the
// anchor text shown to the recipient when the URL came from an HTML <a> element.
type ExtractedURL struct {
	URL         string
	VisibleText string
}

// ParsedAttachment is one decoded attachment with content hashes and the type
// detected from its magic bytes (which may disagree with the declared type).
type ParsedAttachment struct {
	Filename        string
	ContentType     string
	ContentID       string
	Disposition     string
	SHA256          string
	MD5             string
	SHA1            string
	SizeBytes       int64
	Entropy         float64
	ActualExtension string
}

// Recipient is one To/Cc/Bcc address.
type Recipient struct {
	Address     string
	DisplayName string
	Type        string // "to" | "cc" | "bcc"
}

// Parse decodes a raw RFC-822 message into a ParsedEmail. It walks nested
// multipart bodies, decodes content-transfer-encoding, hashes attachments, and
// collects recipients. URL extraction and the HTML→text fallback are applied in
// finalize. An error is returned only when the message headers cannot be read.
func Parse(raw []byte) (*ParsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	pe := &ParsedEmail{Headers: make(map[string]string, len(msg.Header))}
	for k, vv := range msg.Header {
		if len(vv) > 0 {
			pe.Headers[k] = vv[0]
		}
	}
	pe.Subject = decodeWord(msg.Header.Get("Subject"))
	pe.Recipients = parseRecipients(msg.Header)

	// The top-level body is decoded per its own headers; multipart.Part
	// transparently decodes quoted-printable (and hides that header), so
	// decodeBody only needs to handle base64 for nested parts.
	pe.walkPart(
		msg.Header.Get("Content-Type"),
		msg.Header.Get("Content-Transfer-Encoding"),
		msg.Header.Get("Content-Disposition"),
		msg.Body,
	)

	pe.finalize()
	return pe, nil
}

// walkPart dispatches one MIME part: it recurses into multipart containers and
// otherwise classifies the leaf as a body or an attachment. Errors on a single
// part are swallowed so sibling parts still parse.
func (pe *ParsedEmail) walkPart(contentType, cte, disposition string, body io.Reader) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain" // RFC 2045 default.
		params = map[string]string{}
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		mr := multipart.NewReader(body, boundary)
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				return
			}
			pe.walkPart(
				part.Header.Get("Content-Type"),
				part.Header.Get("Content-Transfer-Encoding"),
				part.Header.Get("Content-Disposition"),
				part,
			)
			_ = part.Close()
		}
	}

	decoded, err := decodeBody(body, cte)
	if err != nil {
		return
	}

	disp, dispParams, _ := mime.ParseMediaType(disposition)
	filename := decodeWord(dispParams["filename"])
	if filename == "" {
		filename = decodeWord(params["name"])
	}

	if isAttachment(mediaType, disp, filename) {
		pe.Attachments = append(pe.Attachments, buildAttachment(decoded, mediaType, disp, filename, params["content-id"]))
		return
	}

	switch mediaType {
	case "text/plain":
		pe.BodyPlain = appendText(pe.BodyPlain, string(decoded))
	case "text/html":
		pe.BodyHTML = appendText(pe.BodyHTML, string(decoded))
	}
}

// isAttachment reports whether a leaf part should be treated as an attachment
// rather than a renderable body part.
func isAttachment(mediaType, disposition, filename string) bool {
	if disposition == "attachment" {
		return true
	}
	if disposition == "inline" && filename != "" {
		return true
	}
	return filename != "" && !strings.HasPrefix(mediaType, "text/")
}

// buildAttachment hashes the decoded bytes and detects the real type.
func buildAttachment(data []byte, mediaType, disposition, filename, contentID string) ParsedAttachment {
	sum256 := sha256.Sum256(data)
	sum1 := sha1.Sum(data) //nolint:gosec // IOC matching, not security.
	sum5 := md5.Sum(data)  //nolint:gosec // IOC matching, not security.
	mtype := mimetype.Detect(data)

	return ParsedAttachment{
		Filename:        filename,
		ContentType:     mediaType,
		ContentID:       strings.Trim(contentID, "<>"),
		Disposition:     disposition,
		SHA256:          hex.EncodeToString(sum256[:]),
		MD5:             hex.EncodeToString(sum5[:]),
		SHA1:            hex.EncodeToString(sum1[:]),
		SizeBytes:       int64(len(data)),
		Entropy:         shannonEntropy(data),
		ActualExtension: strings.TrimPrefix(mtype.Extension(), "."),
	}
}

// decodeBody reads a leaf part and applies its content-transfer-encoding.
// quoted-printable from a multipart.Part is already decoded upstream (its header
// is hidden), so only an explicit base64/quoted-printable header is acted on.
func decodeBody(r io.Reader, cte string) ([]byte, error) {
	limited := io.LimitReader(r, maxPartBytes)
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		data, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, limited))
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return data, nil
	case "quoted-printable":
		data, err := io.ReadAll(quotedprintable.NewReader(limited))
		if err != nil {
			return nil, fmt.Errorf("quoted-printable decode: %w", err)
		}
		return data, nil
	default:
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("read part: %w", err)
		}
		return data, nil
	}
}

// parseRecipients collects To/Cc/Bcc addresses from the message header.
func parseRecipients(h mail.Header) []Recipient {
	var out []Recipient
	for _, field := range []struct {
		header string
		kind   string
	}{{"To", "to"}, {"Cc", "cc"}, {"Bcc", "bcc"}} {
		addrs, err := h.AddressList(field.header)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out = append(out, Recipient{Address: a.Address, DisplayName: a.Name, Type: field.kind})
		}
	}
	return out
}

// finalize fills derived fields: it extracts URLs from the available body text
// and is the seam the HTML sanitizer hooks into for richer extraction.
func (pe *ParsedEmail) finalize() {
	corpus := pe.BodyPlain
	if pe.BodyHTML != "" {
		corpus = corpus + "\n" + pe.BodyHTML
	}
	for _, raw := range urlRE.FindAllString(corpus, -1) {
		pe.URLs = append(pe.URLs, ExtractedURL{URL: raw})
	}
	pe.URLs = dedupeURLs(pe.URLs)
}

// dedupeURLs trims trailing punctuation and removes duplicate URLs, keeping the
// first occurrence (and thus its visible text).
func dedupeURLs(in []ExtractedURL) []ExtractedURL {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]ExtractedURL, 0, len(in))
	for _, u := range in {
		u.URL = strings.TrimRight(strings.TrimSpace(u.URL), ".,;:!?)")
		if u.URL == "" {
			continue
		}
		if _, ok := seen[u.URL]; ok {
			continue
		}
		seen[u.URL] = struct{}{}
		out = append(out, u)
	}
	return out
}

// shannonEntropy returns the Shannon entropy (bits/byte, 0–8) of data. High
// entropy is a signal for packed or encrypted attachment payloads.
func shannonEntropy(data []byte) float64 {
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

// decodeWord decodes any RFC 2047 encoded-words in a header value, falling back
// to the raw value on error.
func decodeWord(s string) string {
	if s == "" {
		return ""
	}
	dec := new(mime.WordDecoder)
	if out, err := dec.DecodeHeader(s); err == nil {
		return out
	}
	return s
}

// appendText joins multipart siblings of the same body type with a newline.
func appendText(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "\n" + next
}
