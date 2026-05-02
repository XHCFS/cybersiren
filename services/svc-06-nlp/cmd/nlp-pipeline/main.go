// STUB: pipeline-side binary for svc-06. Distinct from cmd/nlp, which
// remains the standalone HTTP demo. Consumes analysis.text and emits random
// scores on scores.nlp. NO real NLP inference — that lives in the demo path.
package main

import (
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-06-nlp"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:          serviceName,
		NeedsDB:       true,
		NeedsProducer: true,
		Inputs:        []string{contracts.TopicAnalysisText},
		GroupID:       contracts.GroupNLPAnalysis,
		Handler:       svckit.AnalyserHandler(contracts.ComponentNLP, contracts.TopicScoresNLP),
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
