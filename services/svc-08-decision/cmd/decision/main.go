// STUB: replace with real implementation. Consumes emails.scored, computes
// risk_score = avg(component scores), maps to a verdict label per spec §1
// Step 5 thresholds, and emits emails.verdict.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-08-decision"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:          serviceName,
		NeedsDB:       true,
		NeedsProducer: true,
		Inputs:        []string{contracts.TopicEmailsScored},
		GroupID:       contracts.GroupDecisionEngine,
		Handler:       handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, rec *kgo.Record, prod *kafkaproducer.Producer) error {
	var scored contracts.EmailsScored
	if err := json.Unmarshal(rec.Value, &scored); err != nil {
		return fmt.Errorf("decode emails.scored: %w", err)
	}

	risk := averageScores(scored.ComponentScores)
	verdict := contracts.EmailsVerdict{
		Meta:         contracts.NewMeta(scored.Meta.EmailID, scored.Meta.OrgID),
		InternalID:   scored.InternalID,
		FetchedAt:    scored.FetchedAt,
		RiskScore:    risk,
		VerdictLabel: labelFor(risk),
	}

	return prod.Publish(ctx, contracts.TopicEmailsVerdict, scored.Meta.EmailID, verdict)
}

func averageScores(m map[string]float64) float64 {
	if len(m) == 0 {
		return 0
	}
	var sum float64
	for _, v := range m {
		sum += v
	}
	return sum / float64(len(m))
}

func labelFor(score float64) string {
	switch {
	case score <= 25:
		return "benign"
	case score <= 50:
		return "suspicious"
	case score <= 75:
		return "phishing"
	default:
		return "malware"
	}
}
