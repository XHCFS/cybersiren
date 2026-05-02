// STUB: replace with real implementation. Emits random scores on scores.attachment.
package main

import (
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-05-attachment-analysis"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:          serviceName,
		NeedsDB:       true,
		NeedsProducer: true,
		Inputs:        []string{contracts.TopicAnalysisAttachments},
		GroupID:       contracts.GroupAttachmentAnalysis,
		Handler:       svckit.AnalyserHandler(contracts.ComponentAttachment, contracts.TopicScoresAttachment),
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
