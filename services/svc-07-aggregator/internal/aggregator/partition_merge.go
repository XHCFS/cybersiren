package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Valkey field capturing emails.fetched_at (partition key) gathered from
// upstream analysis.plans / scores.* payloads. First non-zero wins (HSETNX).
const fieldPartitionFetchedAt = "__partition_fetched_at"

// Valkey field capturing emails.internal_id — the DB BIGSERIAL surrogate svc-02
// assigns and forwards on scores.header. First non-zero wins (HSETNX). There is
// NO email_id fallback: email_id is a UUIDv7 string and can NOT substitute for
// the int64 internal_id (LANDMINE B). When this field is never set the resolved
// internal_id stays 0 ("unresolved"); an emails.scored with internal_id=0 cannot
// be addressed to a DB verdict row and MUST NOT be published.
const fieldPartitionInternalID = "__partition_internal_id"

// mergePartitionFetchedAt records emails.fetched_at on the aggregation hash
// using HSETNX — all producers for one email should agree; the first writer
// pins the value seen by emails.scored / SVC-08.
func mergePartitionFetchedAt(ctx context.Context, store StateStore, key string, topic string, raw []byte) error {
	ft := extractPartitionFetchedAt(topic, raw)
	if ft.IsZero() {
		return nil
	}
	_, err := store.HSetIfAbsent(ctx, key, fieldPartitionFetchedAt, ft.UTC().Format(startedLayout))
	if err != nil {
		return fmt.Errorf("aggregator HSetIfAbsent partition fetched_at: %w", err)
	}
	return nil
}

func extractPartitionFetchedAt(topic string, raw []byte) time.Time {
	switch topic {
	case contracts.TopicAnalysisPlans:
		var p contracts.AnalysisPlan
		if err := json.Unmarshal(raw, &p); err != nil {
			return time.Time{}
		}
		if !p.Meta.FetchedAt.IsZero() {
			return p.Meta.FetchedAt
		}
	case contracts.TopicScoresHeader:
		var h contracts.ScoresHeaderMessage
		if err := json.Unmarshal(raw, &h); err != nil {
			return time.Time{}
		}
		if !h.FetchedAt.IsZero() {
			return h.FetchedAt
		}
	default:
		var env contracts.ScoreEnvelope //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope decoder.
		if err := json.Unmarshal(raw, &env); err != nil {
			return time.Time{}
		}
		if !env.Meta.FetchedAt.IsZero() {
			return env.Meta.FetchedAt
		}
	}
	return time.Time{}
}

// mergePartitionInternalID records emails.internal_id on the aggregation hash
// via HSETNX. Only scores.header carries it (the always-present component that
// forwards svc-02's DB-assigned id); the first writer pins the value used by
// emails.scored / SVC-08.
func mergePartitionInternalID(ctx context.Context, store StateStore, key string, topic string, raw []byte) error {
	id := extractPartitionInternalID(topic, raw)
	if id == 0 {
		return nil
	}
	_, err := store.HSetIfAbsent(ctx, key, fieldPartitionInternalID, strconv.FormatInt(id, 10))
	if err != nil {
		return fmt.Errorf("aggregator HSetIfAbsent partition internal_id: %w", err)
	}
	return nil
}

func extractPartitionInternalID(topic string, raw []byte) int64 {
	if topic != contracts.TopicScoresHeader {
		return 0
	}
	var h contracts.ScoresHeaderMessage
	if err := json.Unmarshal(raw, &h); err != nil {
		return 0
	}
	return h.InternalID
}

// resolvePartitionKeys derives (internal_id, fetched_at) for emails.scored.
// internal_id is the DB BIGSERIAL surrogate forwarded from scores.header; it is
// distinct from email_id (no invariant). fetched_at must be supplied by upstream
// producers and captured in __partition_fetched_at.
//
// LANDMINE B: email_id is a UUIDv7 string and can NOT substitute for the int64
// internal_id. When no upstream carried __partition_internal_id we return
// internalID=0 (emails.scored Validate downstream rejects a zero key) rather
// than falling back to email_id.
func resolvePartitionKeys(emailID string, state map[string]string) (internalID int64, fetchedAt time.Time, err error) {
	// Prefer the DB-assigned internal_id forwarded from scores.header (svc-02 →
	// analysis.headers → svc-04). Stays 0 when no upstream carried it.
	if v := state[fieldPartitionInternalID]; v != "" {
		if parsed, perr := strconv.ParseInt(v, 10, 64); perr == nil && parsed != 0 {
			internalID = parsed
		}
	}
	s := state[fieldPartitionFetchedAt]
	if s == "" {
		return 0, time.Time{}, fmt.Errorf("aggregator: missing %s (upstream must set meta.fetched_at or scores.header.fetched_at)",
			fieldPartitionFetchedAt)
	}
	fetchedAt, err = time.Parse(startedLayout, s)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("aggregator: parse partition fetched_at: %w", err)
	}
	return internalID, fetchedAt, nil
}
