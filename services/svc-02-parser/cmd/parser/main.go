// svc-02-parser is the (still-skeletal) parser binary used by the pipeline
// spine. It pulls emails.raw, decodes the base64 RFC-822 source, extracts
// URLs / headers / subject+body, and fans out to the 5 analysis.* topics.
//
// The MIME parsing is intentionally minimal — net/mail headers + a regex
// URL sweep over the body. It is good enough to drive svc-04 (which uses
// the headers verbatim) and the real svc-03 URL model and svc-06 NLP
// inference (which only need URLs / subject / body text). When a richer
// parser lands it should replace this binary, not extend it.
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
	"strings"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-02-parser"

// urlRE matches http(s):// URLs in plain text and HTML. Bounded so the
// scanner doesn't get caught on pathological inputs (e.g. an entire
// HTML page rendered without whitespace).
var urlRE = regexp.MustCompile(`https?://[^\s<>"')]{2,2048}`)

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

	subject, body, headers, urls := parseRawEmail(raw)
	meta := contracts.NewMeta(raw.Meta.EmailID, raw.Meta.OrgID)
	key := []byte(raw.Meta.EmailID)

	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, contracts.AnalysisURLs{Meta: meta, URLs: urls}},
		{contracts.TopicAnalysisHeaders, contracts.AnalysisHeaders{Meta: meta, Headers: headers}},
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
		if err := prod.Publish(ctx, key, body, 1); err != nil {
			return fmt.Errorf("publish %s: %w", o.topic, err)
		}
	}

	deps.Log.Info().
		Str("email_id", raw.Meta.EmailID).
		Int("urls", len(urls)).
		Int("subject_len", len(subject)).
		Int("body_len", len(body)).
		Msg("parsed and fanned out")
	return nil
}

// parseRawEmail decodes the base64 RFC-822 source carried on emails.raw and
// extracts the four pipeline-relevant projections: subject, body text, a
// flat header map, and the de-duped list of http(s) URLs. The transport
// envelope's own Headers map (filled by svc-01 ingestion adapters) is
// merged in as a fallback when the raw RFC-822 source is absent or empty.
func parseRawEmail(raw contracts.EmailsRaw) (subject, body string, headers map[string]string, urls []string) {
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
	return subject, body, headers, urls
}

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
