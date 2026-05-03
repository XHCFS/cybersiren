// STUB: replace with real implementation. Consumes analysis.plans + the four
// scores.* topics, gathers per-email_id state in Valkey hash aggregator:{id}
// (TTL 120 s per spec §5), and emits emails.scored once every expected score
// has arrived. NO 30-second timeout in v0 — completion is "all expected
// scores present" only.
//
// Two on-the-wire score shapes coexist for now:
//   - svc-04 (real) emits the flat ScoresHeaderMessage on scores.header
//     (int64 email_id at the top level, integer Score, sub-scores).
//   - svc-03 / svc-05 / svc-06 emit the generic ScoreEnvelope (Meta
//     envelope, float Score). The aggregator handles both.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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

// flexShape decodes the message just far enough to extract email_id and
// org_id, no matter which contract shape is on the wire.
type flexShape struct {
	Meta    *contracts.MessageMeta `json:"meta,omitempty"`
	EmailID int64                  `json:"email_id,omitempty"`
	OrgID   int64                  `json:"org_id,omitempty"`
}

func (f flexShape) ids() (int64, int64) {
	if f.Meta != nil && f.Meta.EmailID != 0 {
		return f.Meta.EmailID, f.Meta.OrgID
	}
	return f.EmailID, f.OrgID
}

func handle(ctx context.Context, msg kafkaconsumer.Message, deps svckit.Deps) error {
	var f flexShape
	if err := json.Unmarshal(msg.Value, &f); err != nil {
		return fmt.Errorf("decode meta: %w", err)
	}
	emailID, orgID := f.ids()
	if emailID == 0 {
		return nil
	}

	key := aggKeyPrefix + strconv.FormatInt(emailID, 10)

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
		score, comp, err := decodeScore(expected, []byte(raw))
		if err != nil {
			return fmt.Errorf("decode score %s: %w", expected, err)
		}
		componentScores[comp] = score
	}
	if missing {
		return nil
	}

	out := contracts.EmailsScored{
		Meta:            contracts.NewMeta(emailID, orgID),
		InternalID:      emailID, // v0: same as logical id
		FetchedAt:       time.Now().UTC(),
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
	if err := prod.Publish(ctx, []byte(strconv.FormatInt(emailID, 10)), body, 1); err != nil {
		return fmt.Errorf("publish emails.scored: %w", err)
	}

	if err := rdb.Do(ctx, rdb.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("del: %w", err)
	}

	return nil
}

// decodeScore handles both the generic ScoreEnvelope (Meta + float Score)
// and svc-04's flat ScoresHeaderMessage (top-level int Score).
func decodeScore(topic string, raw []byte) (score float64, component string, err error) {
	if topic == contracts.TopicScoresHeader {
		var hd contracts.ScoresHeaderMessage
		if err := json.Unmarshal(raw, &hd); err == nil && hd.EmailID != 0 {
			return float64(hd.Score), "header", nil
		}
	}
	var env contracts.ScoreEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, "", fmt.Errorf("unmarshal score envelope for %s: %w", topic, err)
	}
	c := env.Component
	if c == "" {
		c = strings.TrimPrefix(topic, "scores.")
	}
	return env.Score, c, nil
}
