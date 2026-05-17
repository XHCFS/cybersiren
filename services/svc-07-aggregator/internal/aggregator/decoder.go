// Package aggregator implements the SVC-07 score aggregation barrier.
//
// SVC-07 is a stateless fan-in: it consumes analysis.plans and the four
// scores.* topics, gathers per-email state in Valkey, and emits exactly
// one emails.scored message per email_id once all expected component
// scores have arrived (or 30 s have elapsed since the first message,
// whichever comes first).
//
// All per-email state lives in Valkey so multiple SVC-07 instances can
// process messages for the same email_id without coordinating directly.
// See docs/design/svc-07-08-design-brief.md §2 for the full contract.
package aggregator

import (
	"encoding/json"
	"fmt"
	"strings"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// flexShape decodes the message just far enough to extract email_id and
// org_id, no matter which contract shape is on the wire. SVC-04 emits the
// flat ScoresHeaderMessage (top-level email_id) while every other
// upstream uses ScoreEnvelope (nested Meta envelope).
type flexShape struct {
	Meta    *contracts.MessageMeta `json:"meta,omitempty"`
	EmailID int64                  `json:"email_id,omitempty"`
	OrgID   int64                  `json:"org_id,omitempty"`
}

// IDs returns (email_id, org_id) regardless of which envelope shape was
// on the wire. Returns zero values if neither shape contains them.
func (f flexShape) IDs() (int64, int64) {
	if f.Meta != nil && f.Meta.EmailID != 0 {
		return f.Meta.EmailID, f.Meta.OrgID
	}
	return f.EmailID, f.OrgID
}

// extractIDs runs flexShape over the raw kafka payload. Returns an error
// only when JSON is malformed; an unknown shape (no IDs found) is signalled
// via emailID == 0.
func extractIDs(raw []byte) (emailID, orgID int64, err error) {
	var f flexShape
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, 0, fmt.Errorf("decode meta: %w", err)
	}
	emailID, orgID = f.IDs()
	return emailID, orgID, nil
}

// decodeScoreInt extracts the integer 0..100 score from either contract
// shape on the wire. Returns 0 when the score cannot be located so the
// aggregator can still package the upstream message details verbatim.
func decodeScoreInt(topic string, raw []byte) int {
	if topic == contracts.TopicScoresHeader {
		var hd contracts.ScoresHeaderMessage
		if err := json.Unmarshal(raw, &hd); err == nil && hd.EmailID != 0 {
			return clampScore(hd.Score)
		}
	}
	var env contracts.ScoreEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0
	}
	return clampScore(int(env.Score + 0.5))
}

// componentForTopic returns the canonical component name for a scores
// topic. Used for the missing_components list and for diagnostic logs.
func componentForTopic(topic string) string {
	switch topic {
	case contracts.TopicScoresURL:
		return contracts.ComponentURL
	case contracts.TopicScoresHeader:
		return contracts.ComponentHeader
	case contracts.TopicScoresAttachment:
		return contracts.ComponentAttachment
	case contracts.TopicScoresNLP:
		return contracts.ComponentNLP
	default:
		return strings.TrimPrefix(topic, "scores.")
	}
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
