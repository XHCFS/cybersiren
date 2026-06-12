package aggregator

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-07-aggregator/internal/metrics"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

func testPartitionFetchedAt(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 5, 3, 12, 0, 2, 0, time.UTC)
}

func newAgg(t *testing.T, store StateStore, pub Publisher) *Aggregator {
	t.Helper()
	log := zerolog.New(io.Discard)
	a := New(Config{}, store, pub, metrics.New(nil), log)
	a.now = func() time.Time {
		return time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	}
	return a
}

func planMsg(t *testing.T, emailID string, orgID int64, expected ...string) kafkaconsumer.Message {
	t.Helper()
	body, err := json.Marshal(contracts.AnalysisPlan{
		Meta:           contracts.NewMetaWithFetched(emailID, orgID, testPartitionFetchedAt(t)),
		ExpectedScores: expected,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Topic: contracts.TopicAnalysisPlans, Value: body}
}

func envelopeMsg(t *testing.T, topic, emailID string, orgID int64, score float64) kafkaconsumer.Message {
	t.Helper()
	body, err := json.Marshal(contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope test producer.
		Meta: contracts.NewMetaWithFetched(emailID, orgID,
			testPartitionFetchedAt(t)),
		Component: componentForTopic(topic),
		Score:     score,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Topic: topic, Value: body}
}

// headerMsg builds a scores.header carrying the logical email_id (UUIDv7 string)
// and the DB-assigned internal_id svc-04 forwards. internalID may be 0 to model
// the pre-svc-02 interim where no surrogate was forwarded (emails.scored then
// keys on a zero internal_id — there is NO email_id fallback, LANDMINE B).
func headerMsg(t *testing.T, emailID string, orgID, internalID int64, score int) kafkaconsumer.Message {
	t.Helper()
	ft := testPartitionFetchedAt(t)
	body, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID:    emailID,
		InternalID: internalID,
		OrgID:      orgID,
		FetchedAt:  ft,
		Component:  contracts.ComponentHeader,
		Score:      score,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Topic: contracts.TopicScoresHeader, Value: body}
}

func TestHandle_PlanArrivesLast_TriggersEmit(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e42", int64(1)

	// Three scores arrive before the plan.
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 72)))
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 85)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresNLP, emailID, orgID, 60)))

	assert.Equal(t, 0, pub.count(), "must not publish before plan arrives")

	// Plan arrives — completion fires.
	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL,
		contracts.TopicScoresHeader,
		contracts.TopicScoresNLP,
	)))

	require.Equal(t, 1, pub.count())
	var out contracts.EmailsScored
	require.NoError(t, json.Unmarshal(pub.messages[0], &out))
	assert.Equal(t, testPartitionFetchedAt(t).UTC(), out.FetchedAt.UTC())
	// Two-id model: emails.scored carries the forwarded DB internal_id (int64)
	// and the logical email_id (UUIDv7 string) separately — they are NOT equal.
	assert.Equal(t, int64(4242), out.InternalID, "must carry the forwarded scores.header internal_id")
	assert.Equal(t, emailID, out.Meta.EmailID)
	require.NotNil(t, out.URLScore)
	assert.Equal(t, 72, *out.URLScore)
	require.NotNil(t, out.HeaderScore)
	assert.Equal(t, 85, *out.HeaderScore)
	require.NotNil(t, out.NLPScore)
	assert.Equal(t, 60, *out.NLPScore)
	assert.False(t, out.PartialAnalysis)
	assert.False(t, out.TimeoutTriggered)
	assert.NotEmpty(t, out.ComponentDetails.URL)
	assert.NotEmpty(t, out.ComponentDetails.Header)
	assert.NotEmpty(t, out.ComponentDetails.NLP)
	assert.Empty(t, out.ComponentDetails.Attachment)

	// Key removed after publish.
	state, _ := store.HGetAll(ctx, keyForOrgEmail(orgID, emailID))
	assert.Empty(t, state)
}

func TestHandle_DuplicateMessage_DoesNotRepublish(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e7", int64(1)

	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
	// scores.header forwards a non-zero internal_id so the message is addressable
	// and actually publishes (internal_id=0 is dropped at the producer — finding #8).
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 60)))
	require.Equal(t, 1, pub.count())

	// A redelivered duplicate of an already-completed email arrives — it
	// hits an already-deleted key, so it just re-stores fresh state but
	// the plan is no longer present (key was DEL'd). It must NOT publish.
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 60)))
	assert.Equal(t, 1, pub.count(), "duplicate after DEL must not republish")
}

func TestHandle_PublishFailure_ReleasesLockForRetry(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{failNext: 1}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e99", int64(1)

	// scores.header carries a non-zero internal_id so the message is addressable
	// and reaches the publish path (an internal_id=0 message is dropped before
	// publish — finding #8 — and would never exercise the publish-failure branch).
	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID, contracts.TopicScoresHeader)))
	err := a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 80))
	require.Error(t, err, "publish failure must surface as error so offset is not committed")
	assert.Equal(t, 0, pub.count())

	assert.False(t, store.nxHeld(publishLockKey(orgID, emailID)), "publish NX lock must be released after failure")

	// Redelivery succeeds.
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 80)))
	assert.Equal(t, 1, pub.count())
}

func TestSweeper_TimeoutEmitsPartial(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e123", int64(1)

	// Pretend the first message arrived ≥ 30 s ago.
	a.now = func() time.Time { return time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC) }
	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	// scores.header arrives (carrying the addressable internal_id) but URL never
	// does — the partial still has a valid internal_id and must publish on
	// timeout. (A partial whose header never arrives has internal_id=0 and is
	// dropped at the producer — finding #8 — so it can't stand in here.)
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 4242, 60)))

	require.Equal(t, 0, pub.count())

	// Advance time and run a sweeper tick.
	a.now = func() time.Time { return time.Date(2026, 5, 3, 10, 0, 31, 0, time.UTC) }
	NewSweeper(a).tick(ctx)

	require.Equal(t, 1, pub.count(), "timeout must trigger a partial emit")
	var out contracts.EmailsScored
	require.NoError(t, json.Unmarshal(pub.messages[0], &out))
	assert.Equal(t, int64(4242), out.InternalID)
	assert.True(t, out.TimeoutTriggered)
	assert.True(t, out.PartialAnalysis)
	assert.Equal(t, []string{contracts.TopicScoresURL}, out.MissingComponents)
}

// When a bucket completes but no scores.header ever forwarded svc-02's
// internal_id, the resolved internal_id is 0 — the emails.scored cannot be
// addressed to a DB verdict row (there is NO email_id fallback, LANDMINE B) and
// svc-08 would silently discard it. The producer must DROP it loudly (skip the
// emit, commit the offset) and still tear down the bucket + lock so the dead
// email_id does not linger and re-fire. Finding #8.
func TestHandle_UnresolvedInternalID_DropsWithoutPublishing(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e-noid", int64(1)

	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
	// scores.header arrives carrying internal_id=0 (degraded upstream): the bucket
	// completes but the message is unaddressable. Handle must commit (nil), not NACK.
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 0, 60)))

	assert.Equal(t, 0, pub.count(), "unresolved internal_id must NOT be published")

	// Bucket + lock torn down so the dead email_id does not re-fire.
	state, _ := store.HGetAll(ctx, keyForOrgEmail(orgID, emailID))
	assert.Empty(t, state, "bucket must be cleaned up after a drop")
	assert.False(t, store.nxHeld(publishLockKey(orgID, emailID)), "publish lock must be released after a drop")
}

// On the FIRST write for a bucket, Expire is the only thing that ever sets a
// TTL. If it fails the handler must NACK (return error) so the offset is not
// committed and the message redelivers — otherwise the hash leaks TTL-less in
// Valkey forever (the sweeper's no-plan path only Dels the lock).
func TestHandle_FirstWriteExpireFailure_NACKs(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.errOnExpire = func(string) error { return &fakeError{msg: "valkey hiccup"} }
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e555", int64(1)

	// First message for this email → bucket created → Expire fails.
	err := a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50))
	require.Error(t, err, "first-write Expire failure must surface so the offset is not committed")
	assert.Equal(t, 0, pub.count())

	// Once Valkey recovers, the redelivered message succeeds and the bucket
	// carries a TTL (Expire is invoked without error).
	store.errOnExpire = nil
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
}

// A subsequent write (bucket already exists with a TTL) must TOLERATE a
// transient Expire failure — a refresh failure is not fatal because a prior
// write already set the TTL.
func TestHandle_SubsequentWriteExpireFailure_Tolerated(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e556", int64(1)

	// First write succeeds and sets the TTL.
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))

	// Now Expire starts failing — a second write must still commit (nil).
	store.errOnExpire = func(string) error { return &fakeError{msg: "valkey hiccup"} }
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 0, 60)),
		"refresh Expire failure on an existing bucket must not block the offset")
}

// When the completing (Nth) score arrives but the publish lock is already held
// (the sweeper grabbed it mid-emit of a partial), committing would silently
// DROP this arrived component. While the bucket is still present AND complete
// the handler must NACK so the message redelivers and re-contends for the lock.
func TestHandle_CompleteLosesLockRace_NACKsWhileBucketComplete(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := "e557", int64(1)

	// Plan + first score arrive normally (incomplete: header still missing).
	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
	require.Equal(t, 0, pub.count())

	// Simulate the sweeper (or another instance) already holding the publish
	// lock for this email_id when the completing header score arrives.
	got, err := store.SetNXEX(ctx, publishLockKey(orgID, emailID), 180, "1")
	require.NoError(t, err)
	require.True(t, got)

	// Completing score arrives — bucket becomes complete but the lock is held.
	err = a.Handle(ctx, headerMsg(t, emailID, orgID, 0, 60))
	require.Error(t, err, "complete score that loses the lock race must NACK, not commit-and-drop")
	assert.Equal(t, 0, pub.count(), "this handler must not publish; the lock holder owns the emit")

	// Once the lock holder finishes (releases the lock and clears the bucket),
	// the redelivered message hits an empty/no-plan bucket and commits cleanly
	// without republishing — the at-least-once emit already happened upstream.
	require.NoError(t, store.Del(ctx, keyForOrgEmail(orgID, emailID)))
	require.NoError(t, store.Del(ctx, publishLockKey(orgID, emailID)))
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 0, 60)))
	assert.Equal(t, 0, pub.count(), "redelivery after holder cleanup must not double-publish")
}

func TestPackager_FlatHeaderShapeForwardedRaw(t *testing.T) {
	t.Parallel()

	headerBody, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID:   "e1",
		OrgID:     1,
		Component: contracts.ComponentHeader,
		Score:     85,
	})
	require.NoError(t, err)

	planBody, err := json.Marshal(contracts.AnalysisPlan{
		ExpectedScores: []string{contracts.TopicScoresHeader},
	})
	require.NoError(t, err)

	ft := testPartitionFetchedAt(t).UTC().Format(startedLayout)
	state := map[string]string{
		fieldPartitionFetchedAt:     ft,
		fieldPlan:                   string(planBody),
		fieldOrgID:                  "1",
		fieldStartedAt:              time.Now().UTC().Format(startedLayout),
		contracts.TopicScoresHeader: string(headerBody),
	}
	out, err := packageState("e1", 1, state, time.Now().UTC(), false)
	require.NoError(t, err)
	require.NotNil(t, out.HeaderScore)
	assert.Equal(t, 85, *out.HeaderScore)
	// Raw body is forwarded byte-for-byte.
	assert.JSONEq(t, string(headerBody), string(out.ComponentDetails.Header))
}

// emails.scored must carry the DB-assigned internal_id forwarded from
// scores.header (svc-02 -> analysis.headers -> svc-04), NOT email_id — so SVC-08
// updates the parser-owned row. email_id is a UUIDv7 string and can NOT
// substitute for the int64 internal_id (LANDMINE B): when none is forwarded the
// internal_id stays 0.
func TestResolvePartitionKeys_UsesForwardedInternalIDOnly(t *testing.T) {
	t.Parallel()

	headerBody, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: "e999", OrgID: 1, Component: contracts.ComponentHeader, Score: 1,
	})
	require.NoError(t, err)
	planBody, err := json.Marshal(contracts.AnalysisPlan{ExpectedScores: []string{contracts.TopicScoresHeader}})
	require.NoError(t, err)
	ft := testPartitionFetchedAt(t).UTC().Format(startedLayout)
	base := func() map[string]string {
		return map[string]string{
			fieldPartitionFetchedAt:     ft,
			fieldPlan:                   string(planBody),
			fieldOrgID:                  "1",
			fieldStartedAt:              time.Now().UTC().Format(startedLayout),
			contracts.TopicScoresHeader: string(headerBody),
		}
	}

	st := base()
	st[fieldPartitionInternalID] = "42"
	out, err := packageState("e999", 1, st, time.Now().UTC(), false)
	require.NoError(t, err)
	assert.Equal(t, int64(42), out.InternalID, "must use the forwarded internal_id, not email_id")

	out2, err := packageState("e999", 1, base(), time.Now().UTC(), false)
	require.NoError(t, err)
	assert.Equal(t, int64(0), out2.InternalID, "stays 0 when none forwarded — no email_id fallback")
}

// A message-driven publish must wait while scores.header is present with a real
// internal_id but __partition_internal_id hasn't been merged yet (the HSET-field
// then HSETNX-id race) — otherwise emails.scored mis-keys off email_id. A header
// that carried internal_id==0 is never coming, so we must NOT wait.
func TestInternalIDPending(t *testing.T) {
	t.Parallel()

	headerWithID, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: "e999", OrgID: 1, Component: contracts.ComponentHeader, InternalID: 42,
	})
	require.NoError(t, err)
	headerNoID, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: "e999", OrgID: 1, Component: contracts.ComponentHeader, InternalID: 0,
	})
	require.NoError(t, err)

	t.Run("partition id already merged -> not pending", func(t *testing.T) {
		st := map[string]string{
			contracts.TopicScoresHeader: string(headerWithID),
			fieldPartitionInternalID:    "42",
		}
		assert.False(t, internalIDPending(st))
	})
	t.Run("scores.header not yet arrived -> not pending", func(t *testing.T) {
		assert.False(t, internalIDPending(map[string]string{}))
	})
	t.Run("header present with real id, partition field lagging -> pending", func(t *testing.T) {
		st := map[string]string{contracts.TopicScoresHeader: string(headerWithID)}
		assert.True(t, internalIDPending(st))
	})
	t.Run("header carried id==0 (never coming) -> not pending", func(t *testing.T) {
		st := map[string]string{contracts.TopicScoresHeader: string(headerNoID)}
		assert.False(t, internalIDPending(st))
	})
}

func TestExtractIDs_EnvelopeAndFlatShapes(t *testing.T) {
	t.Parallel()

	envBody, _ := json.Marshal(contracts.ScoreEnvelope{ //nolint:staticcheck // G13: sanctioned legacy ScoreEnvelope test producer.
		Meta: contracts.NewMeta("e11", 22), Component: "url", Score: 50,
	})
	hdrBody, _ := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: "e33", OrgID: 44, Component: "header", Score: 70,
	})

	eid, oid, err := extractIDs(envBody)
	require.NoError(t, err)
	assert.Equal(t, "e11", eid)
	assert.Equal(t, int64(22), oid)

	eid, oid, err = extractIDs(hdrBody)
	require.NoError(t, err)
	assert.Equal(t, "e33", eid)
	assert.Equal(t, int64(44), oid)
}

func TestKeyForOrgEmail_Deterministic(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "aggregator:1:e42", keyForOrgEmail(1, "e42"))
	// A UUIDv7 email_id (hyphens/hex) is appended verbatim after the org segment.
	assert.Equal(t, "aggregator:2:01890000-0000-7000-8000-000000000042", keyForOrgEmail(2, "01890000-0000-7000-8000-000000000042"))
}

func TestIsEmailAggregatorKey(t *testing.T) {
	t.Parallel()
	assert.True(t, isEmailAggregatorKey(keyForOrgEmail(1, "e42")))
	assert.False(t, isEmailAggregatorKey(publishLockKey(1, "e42")), "publish lock keys must not be swept as buckets")
}

func TestParseAggregatorBucketKey(t *testing.T) {
	t.Parallel()
	// LANDMINE A: the email segment is now a UUIDv7 string returned verbatim;
	// only the org segment is integer-parsed (split on the LAST ":").
	o, e, ok := parseAggregatorBucketKey("aggregator:7:01890000-0000-7000-8000-000000000099")
	require.True(t, ok)
	assert.Equal(t, int64(7), o)
	assert.Equal(t, "01890000-0000-7000-8000-000000000099", e)

	o2, e2, ok2 := parseAggregatorBucketKey("aggregator:7:99")
	require.True(t, ok2)
	assert.Equal(t, int64(7), o2)
	assert.Equal(t, "99", e2)

	_, _, bad := parseAggregatorBucketKey("aggregator:notnum:1")
	assert.False(t, bad)

	_, _, lock := parseAggregatorBucketKey("aggregator:publock:7:99")
	assert.False(t, lock)

	_, _, legacy := parseAggregatorBucketKey("aggregator:42")
	assert.False(t, legacy, "an org-only key (no email segment) must not parse")
}
