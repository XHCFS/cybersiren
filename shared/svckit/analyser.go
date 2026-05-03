package svckit

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

// AnalyserHandler returns a Handler suitable for an analysis.* → scores.*
// stub. It decodes the meta envelope from the inbound record, sleeps a few
// random milliseconds to simulate work, and emits a ScoreEnvelope with a
// random 0..100 score.
//
// STUB: replace with real analyser logic.
func AnalyserHandler(component, outTopic string) Handler {
	return func(ctx context.Context, msg kafkaconsumer.Message, deps Deps) error {
		var env struct {
			Meta contracts.MessageMeta `json:"meta"`
		}
		if err := json.Unmarshal(msg.Value, &env); err != nil {
			return fmt.Errorf("decode meta from %s: %w", msg.Topic, err)
		}

		time.Sleep(time.Duration(rand.IntN(50)) * time.Millisecond) //nolint:gosec // not security-sensitive

		out := contracts.ScoreEnvelope{
			Meta:      contracts.NewMeta(env.Meta.EmailID, env.Meta.OrgID),
			Component: component,
			Score:     float64(rand.IntN(101)), //nolint:gosec
		}

		body, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", outTopic, err)
		}

		prod, ok := deps.Producers[outTopic]
		if !ok {
			return fmt.Errorf("svckit: producer for %s not configured (add to ProducerTopics)", outTopic)
		}
		if err := prod.Publish(ctx, []byte(strconv.FormatInt(env.Meta.EmailID, 10)), body, 1); err != nil {
			return fmt.Errorf("publish %s: %w", outTopic, err)
		}
		return nil
	}
}
