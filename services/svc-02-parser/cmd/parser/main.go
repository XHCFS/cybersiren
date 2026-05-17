// svc-02-parser is the (still-skeletal) parser binary used by the pipeline
// spine. It pulls emails.raw, decodes the base64 RFC-822 source, extracts
// URLs / headers / subject+body, and fans out to the 5 analysis.* topics.
//
// analysis.headers uses svc-04's authoritative AnalysisHeadersMessage
// shape (int64 IDs, parsed structural fields). The other topics use the
// generic kafka.MessageMeta envelope. svc-04's processor reads the
// flat shape directly; svc-03 / svc-06 read the generic envelope.
//
// The MIME parsing here is intentionally minimal — net/mail headers + a
// regex URL sweep. It is good enough to drive svc-04's auth/structural
// signal extractors and the real svc-03 URL model and svc-06 NLP. When
// a richer parser lands it should replace this binary, not extend it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-02-parser"

// urlRE matches http(s):// URLs in plain text and HTML. RE2 caps the
// repetition counter, so we use `+` and trim ourselves later.
var urlRE = regexp.MustCompile(`https?://[^\s<>"')]+`)

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

	parsedHeaders, subject, body, urls := parseRawEmail(raw)
	key := []byte(strconv.FormatInt(raw.Meta.EmailID, 10))
	fetchedAt := raw.FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	meta := contracts.NewMetaWithFetched(raw.Meta.EmailID, raw.Meta.OrgID, fetchedAt)

	headersMsg := buildAnalysisHeaders(raw.Meta.EmailID, raw.Meta.OrgID, fetchedAt, parsedHeaders)

	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, contracts.AnalysisURLs{Meta: meta, URLs: urls}},
		{contracts.TopicAnalysisHeaders, headersMsg},
		{contracts.TopicAnalysisAttachments, contracts.AnalysisAttachments{Meta: meta, Attachments: nil}},
		{contracts.TopicAnalysisText, contracts.AnalysisText{Meta: meta, Subject: subject, Body: body}},
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
		Int("subject_len", len(subject)).
		Int("body_len", len(body)).
		Msg("parsed and fanned out")
	return nil
}

// parseRawEmail decodes the base64 RFC-822 source and returns the flat
// header map, subject, body, and a deduplicated URL list.
func parseRawEmail(raw contracts.EmailsRaw) (headers map[string]string, subject, body string, urls []string) {
	headers = map[string]string{}
	for k, v := range raw.Headers {
		headers[k] = v
	}

	if raw.RawMessageB64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw.RawMessageB64); err == nil {
			if mm, err := mail.ReadMessage(strings.NewReader(string(decoded))); err == nil {
				for k, vv := range mm.Header {
					if len(vv) == 0 {
						continue
					}
					headers[k] = vv[0]
				}
				subject = headers["Subject"]
				if bytes, err := io.ReadAll(mm.Body); err == nil {
					body = string(bytes)
				}
			}
		}
	}

	if subject == "" {
		subject = headers["Subject"]
	}

	urls = uniqueStrings(urlRE.FindAllString(body, -1))
	return headers, subject, body, urls
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

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimRight(s, ".,;:")
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

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
