package aggregator

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Constants for the well-known Valkey hash field names used by the
// aggregator. The leading double underscore avoids any collision with the
// dynamic per-topic field names (which all start with "scores." or
// "analysis.").
const (
	fieldPlan      = "__plan"
	fieldStartedAt = "__started_at"
	fieldOrgID     = "__org_id"

	keyPrefix     = "aggregator:"
	hashTTLSecs   = 120
	timeoutSecs   = 30
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
	emailID string,
	orgID int64,
	state map[string]string,
	startedAt time.Time,
	timeoutTriggered bool,
) (contracts.EmailsScored, error) {
	planRaw, ok := state[fieldPlan]
	if !ok {
		return contracts.EmailsScored{}, fmt.Errorf("aggregator: package called without plan for email_id=%s", emailID)
	}
	var plan contracts.AnalysisPlan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		return contracts.EmailsScored{}, fmt.Errorf("decode plan: %w", err)
	}

	internalID, fetchedAt, err := resolvePartitionKeys(emailID, state)
	if err != nil {
		return contracts.EmailsScored{}, err
	}

	meta := contracts.NewMeta(emailID, orgID)
	meta.FetchedAt = fetchedAt

	out := contracts.EmailsScored{
		Meta:             meta,
		InternalID:       internalID,
		FetchedAt:        fetchedAt,
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

// internalIDPending reports whether a message-driven publish must briefly wait
// for the DB internal_id to be merged before emitting emails.scored.
//
// scores.header forwards svc-02's BIGSERIAL internal_id; its handler writes the
// scores.header field (HSET) and then merges __partition_internal_id (HSETNX) as
// two separate Valkey ops. A concurrent handler for another component can read a
// state snapshot in that window — scores.header field present (so the bucket
// looks complete) but __partition_internal_id not yet visible — and would
// publish with the email_id fallback, mis-keying the verdict off the parser row.
//
// We wait only when scores.header is present AND carried a non-zero internal_id
// but the partition field is not yet set: the merge is just lagging and the
// scores.header handler (or a #190 redelivery if it errored) will complete it.
// A scores.header that carried internal_id==0 (degraded upstream) is "never
// coming", so we do NOT wait — the email_id fallback stands. The globally-last
// completing handler always observes the merged id, so this never deadlocks; the
// timeout sweeper is the backstop regardless.
func internalIDPending(state map[string]string) bool {
	if state[fieldPartitionInternalID] != "" {
		return false
	}
	headerRaw, ok := state[contracts.TopicScoresHeader]
	if !ok {
		return false
	}
	var h contracts.ScoresHeaderMessage
	if err := json.Unmarshal([]byte(headerRaw), &h); err != nil {
		return false
	}
	return h.InternalID != 0
}

// keyForOrgEmail returns the aggregation hash key scoped by tenant so two
// orgs cannot clobber each other's buckets when email_id overlaps. email_id is
// a UUIDv7 string (#142), appended verbatim after the org segment.
func keyForOrgEmail(orgID int64, emailID string) string {
	return fmt.Sprintf("%s%d:%s", keyPrefix, orgID, emailID)
}

// publishLockKey is a short-TTL NX key for exclusive emails.scored emit.
func publishLockKey(orgID int64, emailID string) string {
	return fmt.Sprintf("%spublock:%d:%s", keyPrefix, orgID, emailID)
}

// parseAggregatorBucketKey parses aggregator:{org}:{email}. Returns ok=false for
// lock keys (aggregator:publock:...) or malformed keys.
//
// LANDMINE A: email_id is now a UUIDv7 string whose hyphens/hex would fail
// strconv.ParseInt. We split on the LAST ":" so the org segment is the int64
// prefix and everything after it is the raw email_id string (a UUID contains no
// ":"); only the org segment is integer-parsed.
func parseAggregatorBucketKey(key string) (orgID int64, emailID string, ok bool) {
	if !strings.HasPrefix(key, keyPrefix) {
		return 0, "", false
	}
	rest := key[len(keyPrefix):]
	if strings.HasPrefix(rest, "publock:") {
		return 0, "", false
	}
	colon := strings.LastIndexByte(rest, ':')
	if colon <= 0 || colon >= len(rest)-1 {
		return 0, "", false
	}
	orgStr, emailStr := rest[:colon], rest[colon+1:]
	o, err1 := strconv.ParseInt(orgStr, 10, 64)
	if err1 != nil || o <= 0 || emailStr == "" {
		return 0, "", false
	}
	return o, emailStr, true
}
