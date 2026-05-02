// STUB: replace with real implementation. Consumes emails.raw and fans out
// minimal payloads to the 5 analysis.* topics. NO real MIME parsing — outputs
// are synthesised from the input envelope plus one fake URL/header/attachment.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-02-parser"

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

	meta := contracts.NewMeta(raw.Meta.EmailID, raw.Meta.OrgID)
	key := []byte(raw.Meta.EmailID)

	out := []struct {
		topic   string
		payload any
	}{
		{contracts.TopicAnalysisURLs, contracts.AnalysisURLs{Meta: meta, URLs: []string{"https://example.com/stub"}}},
		{contracts.TopicAnalysisHeaders, contracts.AnalysisHeaders{Meta: meta, Headers: raw.Headers}},
		{contracts.TopicAnalysisAttachments, contracts.AnalysisAttachments{Meta: meta, Attachments: nil}},
		{contracts.TopicAnalysisText, contracts.AnalysisText{Meta: meta, Subject: "stub-subject", Body: "stub-body"}},
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
	return nil
}
