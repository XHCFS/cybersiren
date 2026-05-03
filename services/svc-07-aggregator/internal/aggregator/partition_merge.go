package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Valkey field capturing emails.fetched_at (partition key) gathered from
// upstream analysis.plans / scores.* payloads. First non-zero wins (HSETNX).
const fieldPartitionFetchedAt = "__partition_fetched_at"

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
		var env contracts.ScoreEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return time.Time{}
		}
		if !env.Meta.FetchedAt.IsZero() {
			return env.Meta.FetchedAt
		}
	}
	return time.Time{}
}

// resolvePartitionKeys derives (internal_id, fetched_at) for emails.scored.
// Per ARCH-SPEC, Kafka meta.email_id equals emails.internal_id; fetched_at
// must be supplied by upstream producers and captured in __partition_fetched_at.
func resolvePartitionKeys(emailID int64, state map[string]string) (internalID int64, fetchedAt time.Time, err error) {
	internalID = emailID
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
