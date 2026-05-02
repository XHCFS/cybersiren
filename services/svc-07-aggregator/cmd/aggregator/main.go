// STUB: replace with real implementation. Consumes analysis.plans + the four
// scores.* topics, gathers per-email_id state in Valkey hash aggregator:{id}
// (TTL 120 s per spec §5), and emits emails.scored once every expected score
// has arrived. NO 30-second timeout in v0 — completion is "all expected
// scores present" only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName       = "svc-07-aggregator"
	aggKeyPrefix      = "aggregator:"
	aggHashTTLSeconds = 120
	planField         = "__plan"
)

var rdb valkeygo.Client

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsValkey:    true,
		ProducerTopics: []string{contracts.TopicEmailsScored},
		ConsumerTopics: []string{
			contracts.TopicAnalysisPlans,
			contracts.TopicScoresURL,
			contracts.TopicScoresHeader,
			contracts.TopicScoresAttachment,
			contracts.TopicScoresNLP,
		},
		GroupID: contracts.GroupAggregator,
		OnReady: func(ctx context.Context, deps svckit.Deps) error {
			rdb = deps.Valkey
			return nil
		},
		Handler: handle,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var meta struct {
		Meta contracts.MessageMeta `json:"meta"`
	}
	if err := json.Unmarshal(msg.Value, &meta); err != nil {
		return fmt.Errorf("decode meta: %w", err)
	}
	emailID := meta.Meta.EmailID
	if emailID == "" {
		return nil
	}

	key := aggKeyPrefix + emailID

	field := msg.Topic
	if msg.Topic == contracts.TopicAnalysisPlans {
		field = planField
	}

	if err := rdb.Do(ctx, rdb.B().Hset().Key(key).FieldValue().FieldValue(field, string(msg.Value)).Build()).Error(); err != nil {
		return fmt.Errorf("hset: %w", err)
	}
	if err := rdb.Do(ctx, rdb.B().Expire().Key(key).Seconds(aggHashTTLSeconds).Build()).Error(); err != nil {
		return fmt.Errorf("expire: %w", err)
	}

	all, err := rdb.Do(ctx, rdb.B().Hgetall().Key(key).Build()).AsStrMap()
	if err != nil {
		return fmt.Errorf("hgetall: %w", err)
	}

	planRaw, hasPlan := all[planField]
	if !hasPlan {
		return nil
	}
	var plan contracts.AnalysisPlan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}

	componentScores := map[string]float64{}
	missing := false
	for _, expected := range plan.ExpectedScores {
		raw, ok := all[expected]
		if !ok {
			missing = true
			break
		}
		var env contracts.ScoreEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			return fmt.Errorf("decode score %s: %w", expected, err)
		}
		c := env.Component
		if c == "" {
			c = strings.TrimPrefix(expected, "scores.")
		}
		componentScores[c] = env.Score
	}
	if missing {
		return nil
	}

	out := contracts.EmailsScored{
		Meta:            contracts.NewMeta(emailID, plan.Meta.OrgID),
		InternalID:      "fake-internal-" + emailID, // v0 placeholder
		FetchedAt:       time.Now().UTC(),           // v0 placeholder
		ComponentScores: componentScores,
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal emails.scored: %w", err)
	}
	prod, ok := deps.Producers[contracts.TopicEmailsScored]
	if !ok {
		return fmt.Errorf("svc-07: producer for %s not configured", contracts.TopicEmailsScored)
	}
	if err := prod.Publish(ctx, []byte(emailID), body, 1); err != nil {
		return fmt.Errorf("publish emails.scored: %w", err)
	}

	if err := rdb.Do(ctx, rdb.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("del: %w", err)
	}

	return nil
}
