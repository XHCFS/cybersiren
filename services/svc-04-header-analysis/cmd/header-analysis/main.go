// STUB: replace with real implementation. Emits random scores on scores.header.
package main

import (
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-04-header-analysis"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:          serviceName,
		NeedsDB:       true,
		NeedsProducer: true,
		Inputs:        []string{contracts.TopicAnalysisHeaders},
		GroupID:       contracts.GroupHeaderAnalysis,
		Handler:       svckit.AnalyserHandler(contracts.ComponentHeader, contracts.TopicScoresHeader),
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
