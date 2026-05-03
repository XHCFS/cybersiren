package aggregator

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Constants for the well-known Valkey hash field names used by the
// aggregator. The leading double underscore avoids any collision with the
// dynamic per-topic field names (which all start with "scores." or
// "analysis.").
const (
	fieldPlan       = "__plan"
	fieldStartedAt  = "__started_at"
	fieldOrgID      = "__org_id"
	fieldPublishing = "__publishing"

	keyPrefix    = "aggregator:"
	hashTTLSecs  = 120
	timeoutSecs  = 30
	startedLayout = time.RFC3339Nano
)

// packageState turns a Valkey hash snapshot into an EmailsScored message,
// honouring the AnalysisPlan's expected_scores list. It MUST be called
// only when the plan field is present (or when the timeout sweeper has
// decided to emit a partial result, in which case missing scores are
// listed in MissingComponents).
//
// startedAt is the time the first message for this email_id arrived
// (parsed from the hash's __started_at field).
//
// timeoutTriggered marks whether the emit was forced by the 30 s
// timeout sweeper. Together with PartialAnalysis it gives downstream
// consumers (SVC-08) the full picture: timeout=true & partial=false is
// impossible by construction; partial=true & timeout=false means the
// plan declared fewer than 4 components (e.g. an email without
// attachments).
func packageState(
	emailID, orgID int64,
	state map[string]string,
	startedAt time.Time,
	timeoutTriggered bool,
) (contracts.EmailsScored, error) {
	planRaw, ok := state[fieldPlan]
	if !ok {
		return contracts.EmailsScored{}, fmt.Errorf("aggregator: package called without plan for email_id=%d", emailID)
	}
	var plan contracts.AnalysisPlan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		return contracts.EmailsScored{}, fmt.Errorf("decode plan: %w", err)
	}

	out := contracts.EmailsScored{
		Meta:             contracts.NewMeta(emailID, orgID),
		InternalID:       emailID, // v0: same as logical id (will be replaced by SVC-01 ingest)
		FetchedAt:        firstFetchedAt(state),
		ComponentDetails: contracts.ComponentDetails{},
		TimeoutTriggered: timeoutTriggered,
	}
	if !startedAt.IsZero() {
		out.AggregationLatencyMS = time.Since(startedAt).Milliseconds()
	}

	missing := []string{}
	for _, expected := range plan.ExpectedScores {
		raw, ok := state[expected]
		if !ok {
			missing = append(missing, expected)
			continue
		}
		score := decodeScoreInt(expected, []byte(raw))
		switch expected {
		case contracts.TopicScoresURL:
			s := score
			out.URLScore = &s
			out.ComponentDetails.URL = json.RawMessage(raw)
		case contracts.TopicScoresHeader:
			s := score
			out.HeaderScore = &s
			out.ComponentDetails.Header = json.RawMessage(raw)
		case contracts.TopicScoresAttachment:
			s := score
			out.AttachmentScore = &s
			out.ComponentDetails.Attachment = json.RawMessage(raw)
		case contracts.TopicScoresNLP:
			s := score
			out.NLPScore = &s
			out.ComponentDetails.NLP = json.RawMessage(raw)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		out.MissingComponents = missing
		out.PartialAnalysis = true
	}
	return out, nil
}

// completionStatus determines whether the gathered state is sufficient
// to publish a complete (non-partial) emails.scored message. It returns
// (complete, hasPlan):
//
//   - complete=true  → all expected scores present.
//   - hasPlan=false  → cannot evaluate; wait for analysis.plans.
func completionStatus(state map[string]string) (complete, hasPlan bool) {
	planRaw, ok := state[fieldPlan]
	if !ok {
		return false, false
	}
	var plan contracts.AnalysisPlan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		// A malformed plan is treated as "no plan" — the next score
		// arrival will retry. The handler logs the decode error.
		return false, false
	}
	for _, expected := range plan.ExpectedScores {
		if _, ok := state[expected]; !ok {
			return false, true
		}
	}
	return true, true
}

// firstFetchedAt is a pragmatic placeholder until SVC-01 (ingestion)
// lands and every analysis.* / scores.* message carries fetched_at
// end-to-end. The aggregator's emails.scored output declares the
// partition key (internal_id, fetched_at) used by SVC-08 to write to
// Postgres; for now both internal_id and fetched_at are derived from
// the inbound logical email_id and the current wall-clock.
//
// See contracts/kafka/header.go's CONTRACT NOTE which tracks the same
// follow-up: "aligning these two representations is a tracked
// architectural follow-up".
func firstFetchedAt(_ map[string]string) time.Time {
	return time.Now().UTC()
}

// keyForEmailID returns the canonical Valkey key.
func keyForEmailID(emailID int64) string {
	return keyPrefix + fmt.Sprintf("%d", emailID)
}
