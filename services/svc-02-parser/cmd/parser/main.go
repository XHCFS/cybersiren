// svc-02-parser is the parser binary on the pipeline spine. It pulls
// emails.raw, parses the base64 RFC-822 source into a structured email
// (headers, decoded bodies, hashed attachments, extracted URLs, recipients),
// persists it to Postgres in one transaction, and fans the analysis facets out
// to the 5 analysis.* topics.
//
// Persistence makes internal_id = the envelope email_id so SVC-08's later
// emails UPDATE targets the row this service writes (ARCH-SPEC §1 step 2).
//
// analysis.headers uses svc-04's authoritative AnalysisHeadersMessage shape
// (int64 IDs, parsed structural fields). The other topics use the generic
// kafka.MessageMeta envelope. svc-04's processor reads the flat shape directly;
// svc-03 / svc-06 read the generic envelope.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-02-parser/internal/email"
	"github.com/saif/cybersiren/services/svc-02-parser/internal/store"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-02-parser"

// dbWriteRetries is the number of retries (beyond the first attempt) for the
// per-email persistence transaction before the handler returns an error and the
// Kafka offset is left uncommitted.
const dbWriteRetries = 2

func main() {
	outputs := []string{
		contracts.TopicAnalysisURLs,
		contracts.TopicAnalysisHeaders,
		contracts.TopicAnalysisAttachments,
		contracts.TopicAnalysisText,
		contracts.TopicAnalysisPlans,
	}

	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: outputs,
		ConsumerTopics: []string{contracts.TopicEmailsRaw},
		GroupID:        contracts.GroupParser,
		Handler:        handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var raw contracts.EmailsRaw
	if err := json.Unmarshal(msg.Value, &raw); err != nil {
		return fmt.Errorf("decode emails.raw: %w", err)
	}

	fetchedAt := raw.FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	meta := contracts.NewMetaWithFetched(raw.Meta.EmailID, raw.Meta.OrgID, fetchedAt)

	parsed := parseEmail(raw)
	headersMsg := buildAnalysisHeaders(raw.Meta.EmailID, raw.Meta.OrgID, fetchedAt, parsed.Headers)

	// Persist before fan-out: a failed write returns an error so the Kafka
	// offset is not committed and the email is redelivered rather than analysed
	// against a row that was never stored.
	if err := persistEmail(ctx, deps, raw, fetchedAt, parsed, headersMsg); err != nil {
		return err
	}

	urls := urlStrings(parsed.URLs)
	attachments := contractAttachments(parsed.Attachments)
	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, contracts.AnalysisURLs{Meta: meta, URLs: urls}},
		{contracts.TopicAnalysisHeaders, headersMsg},
		{contracts.TopicAnalysisAttachments, contracts.AnalysisAttachments{Meta: meta, Attachments: attachments}},
		{contracts.TopicAnalysisText, contracts.AnalysisText{Meta: meta, Subject: parsed.Subject, Body: parsed.BodyPlain}},
		{contracts.TopicAnalysisPlans, contracts.AnalysisPlan{
			Meta: meta,
			ExpectedScores: []string{
				contracts.TopicScoresURL,
				contracts.TopicScoresHeader,
				contracts.TopicScoresAttachment,
				contracts.TopicScoresNLP,
			},
		}},
	}

	key := []byte(strconv.FormatInt(raw.Meta.EmailID, 10))
	for _, o := range out {
		body, err := json.Marshal(o.payload)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", o.topic, err)
		}
		prod, ok := deps.Producers[o.topic]
		if !ok {
			return fmt.Errorf("svc-02: producer %s not configured", o.topic)
		}
		if err := prod.Publish(ctx, key, body, 1); err != nil { // +1 kafka retry after first
			return fmt.Errorf("publish %s: %w", o.topic, err)
		}
	}

	deps.Log.Info().
		Int64("email_id", raw.Meta.EmailID).
		Int("urls", len(urls)).
		Int("attachments", len(parsed.Attachments)).
		Int("recipients", len(parsed.Recipients)).
		Int("subject_len", len(parsed.Subject)).
		Int("body_len", len(parsed.BodyPlain)).
		Msg("parsed, persisted, and fanned out")
	return nil
}

// parseEmail parses the base64 RFC-822 source into a structured email, merging
// in any envelope headers the adapter carried separately. When the source is
// absent or unparseable it falls back to an email built from the envelope
// headers alone so the pipeline still advances.
func parseEmail(raw contracts.EmailsRaw) *email.ParsedEmail {
	if raw.RawMessageB64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw.RawMessageB64); err == nil {
			if pe, err := email.Parse(decoded); err == nil {
				mergeHeaders(pe.Headers, raw.Headers)
				if pe.Subject == "" {
					pe.Subject = pe.Headers["Subject"]
				}
				return pe
			}
		}
	}

	pe := &email.ParsedEmail{Headers: map[string]string{}}
	mergeHeaders(pe.Headers, raw.Headers)
	pe.Subject = pe.Headers["Subject"]
	return pe
}

// persistEmail projects the parsed email + header message into an EmailRecord
// and writes it (plus its junction rows) in one transaction.
func persistEmail(
	ctx context.Context,
	deps svckit.Deps,
	raw contracts.EmailsRaw,
	fetchedAt time.Time,
	parsed *email.ParsedEmail,
	h contracts.AnalysisHeadersMessage,
) error {
	messageID := raw.MessageID
	if messageID == "" {
		messageID = parsed.Headers["Message-Id"]
	}

	rec := store.EmailRecord{
		InternalID:     raw.Meta.EmailID,
		FetchedAt:      fetchedAt,
		OrgID:          raw.Meta.OrgID,
		MessageID:      messageID,
		SenderName:     h.SenderName,
		SenderEmail:    h.SenderEmail,
		SenderDomain:   h.SenderDomain,
		ReplyToEmail:   h.ReplyToEmail,
		ReturnPath:     h.ReturnPath,
		AuthSPF:        h.AuthSPF,
		AuthDKIM:       h.AuthDKIM,
		AuthDMARC:      h.AuthDMARC,
		AuthARC:        h.AuthARC,
		MailerAgent:    h.MailerAgent,
		InReplyTo:      h.InReplyTo,
		ReferencesList: referencesList(parsed.Headers["References"]),
		ContentCharset: h.ContentCharset,
		Precedence:     h.Precedence,
		ListID:         h.ListID,
		Subject:        parsed.Subject,
		SentTimestamp:  sentTimestampPtr(parsed.Headers["Date"]),
		HeadersJSON:    h.HeadersJSON,
		BodyPlain:      parsed.BodyPlain,
		BodyHTML:       parsed.BodyHTML,
	}

	w := store.NewWriter(deps.Pool, dbWriteRetries, deps.Log)
	if err := w.Persist(ctx, rec, parsed.URLs, parsed.Attachments, parsed.Recipients); err != nil {
		return fmt.Errorf("persist email %d: %w", raw.Meta.EmailID, err)
	}
	return nil
}

// mergeHeaders copies src entries into dst without overwriting headers already
// parsed from the RFC-822 source.
func mergeHeaders(dst, src map[string]string) {
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
}

// urlStrings projects extracted URLs down to the slim []string wire shape.
func urlStrings(urls []email.ExtractedURL) []string {
	if len(urls) == 0 {
		return nil
	}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		out = append(out, u.URL)
	}
	return out
}

// contractAttachments maps parsed attachments to the analysis.attachments wire
// shape so SVC-05 can look each one up in attachment_library by sha256.
func contractAttachments(atts []email.ParsedAttachment) []contracts.Attachment {
	if len(atts) == 0 {
		return nil
	}
	out := make([]contracts.Attachment, 0, len(atts))
	for _, a := range atts {
		out = append(out, contracts.Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			SizeBytes:   a.SizeBytes,
			SHA256:      a.SHA256,
		})
	}
	return out
}

// referencesList splits the RFC 5322 References header into individual
// message-ids, or nil when the header is absent.
func referencesList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}

// sentTimestampPtr parses the Date header to a Unix epoch, returning nil (SQL
// NULL) when the header is missing or unparseable so it is distinguishable from
// a genuine epoch-zero timestamp.
func sentTimestampPtr(dateHeader string) *int64 {
	if strings.TrimSpace(dateHeader) == "" {
		return nil
	}
	t, err := mail.ParseDate(dateHeader)
	if err != nil {
		return nil
	}
	ts := t.Unix()
	return &ts
}

// buildAnalysisHeaders projects the flat header map into svc-04's
// AnalysisHeadersMessage. It does the minimum needed for svc-04's
// auth / reputation / structural extractors to fire — sender_email,
// sender_domain, auth_*, originating_ip, hop count, sent timestamp.
func buildAnalysisHeaders(emailID, orgID int64, fetchedAt time.Time, h map[string]string) contracts.AnalysisHeadersMessage {
	from := h["From"]
	senderEmail, senderName := splitEmailAddress(from)
	senderDomain := domainOf(senderEmail)

	auth := parseAuthResults(h["Authentication-Results"])

	hopCount := strings.Count(strings.Join(receivedLines(h), "\n"), "from ")

	sentTS := int64(0)
	if dateStr, ok := h["Date"]; ok && dateStr != "" {
		if t, err := mail.ParseDate(dateStr); err == nil {
			sentTS = t.Unix()
		}
	}

	headersJSON, _ := json.Marshal(h)

	return contracts.AnalysisHeadersMessage{
		EmailID:        emailID,
		OrgID:          orgID,
		FetchedAt:      fetchedAt,
		SenderEmail:    senderEmail,
		SenderDomain:   senderDomain,
		SenderName:     senderName,
		ReplyToEmail:   addressOnly(h["Reply-To"]),
		ReturnPath:     addressOnly(h["Return-Path"]),
		MailerAgent:    h["X-Mailer"],
		AuthSPF:        auth["spf"],
		AuthDKIM:       auth["dkim"],
		AuthDMARC:      auth["dmarc"],
		AuthARC:        auth["arc"],
		InReplyTo:      h["In-Reply-To"],
		SentTimestamp:  sentTS,
		ContentCharset: charsetFrom(h["Content-Type"]),
		Precedence:     h["Precedence"],
		ListID:         h["List-Id"],
		HopCount:       hopCount,
		HeadersJSON:    headersJSON,
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func splitEmailAddress(raw string) (addr, name string) {
	a, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw), ""
	}
	return a.Address, a.Name
}

func addressOnly(raw string) string {
	a, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return a.Address
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// parseAuthResults handles the common single-line shape:
//
//	"spf=pass smtp.mailfrom=…; dkim=fail; dmarc=fail"
//
// It does NOT parse the full RFC 8601 grammar — good enough for v0 smoke.
func parseAuthResults(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		for _, k := range []string{"spf", "dkim", "dmarc", "arc"} {
			prefix := k + "="
			if i := strings.Index(strings.ToLower(segment), prefix); i >= 0 {
				rest := segment[i+len(prefix):]
				value := strings.SplitN(rest, " ", 2)[0]
				value = strings.TrimSpace(value)
				if value != "" && out[k] == "" {
					out[k] = value
				}
			}
		}
	}
	return out
}

func receivedLines(h map[string]string) []string {
	out := []string{}
	for k, v := range h {
		if strings.EqualFold(k, "Received") {
			out = append(out, v)
		}
	}
	return out
}

func charsetFrom(contentType string) string {
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "charset=") {
			v := part[len("charset="):]
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
