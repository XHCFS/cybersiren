// STUB: replace with real implementation. Consumes emails.scored, computes
// risk_score = avg(component scores), maps to a verdict label per spec §1
// Step 5 thresholds, and emits emails.verdict.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-08-decision"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		ProducerTopics: []string{contracts.TopicEmailsVerdict},
		ConsumerTopics: []string{contracts.TopicEmailsScored},
		GroupID:        contracts.GroupDecisionEngine,
		Handler:        handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var scored contracts.EmailsScored
	if err := json.Unmarshal(msg.Value, &scored); err != nil {
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

	body, err := json.Marshal(verdict)
	if err != nil {
		return fmt.Errorf("marshal verdict: %w", err)
	}
	prod, ok := deps.Producers[contracts.TopicEmailsVerdict]
	if !ok {
		return fmt.Errorf("svc-08: producer for %s not configured", contracts.TopicEmailsVerdict)
	}
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(scored.Meta.EmailID, 10)), body, 1); err != nil {
		return fmt.Errorf("publish emails.verdict: %w", err)
	}
	return nil
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
