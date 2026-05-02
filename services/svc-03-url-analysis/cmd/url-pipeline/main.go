// STUB: pipeline-side binary for svc-03. Distinct from cmd/url-analysis,
// which remains the standalone HTTP demo. Consumes analysis.urls and emits
// random scores on scores.url. NO ML, NO TI lookups — that lives in the
// real demo path.
package main

import (
	"os"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-03-url-analysis"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: []string{contracts.TopicScoresURL},
		ConsumerTopics: []string{contracts.TopicAnalysisURLs},
		GroupID:        contracts.GroupURLAnalysis,
		Handler:        svckit.AnalyserHandler(contracts.ComponentURL, contracts.TopicScoresURL),
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}
