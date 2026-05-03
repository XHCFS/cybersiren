package aggregator

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
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

func planMsg(t *testing.T, emailID, orgID int64, expected ...string) kafkaconsumer.Message {
	t.Helper()
	body, err := json.Marshal(contracts.AnalysisPlan{
		Meta:           contracts.NewMetaWithFetched(emailID, orgID, testPartitionFetchedAt(t)),
		ExpectedScores: expected,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Topic: contracts.TopicAnalysisPlans, Value: body}
}

func envelopeMsg(t *testing.T, topic string, emailID, orgID int64, score float64) kafkaconsumer.Message {
	t.Helper()
	body, err := json.Marshal(contracts.ScoreEnvelope{
		Meta: contracts.NewMetaWithFetched(emailID, orgID,
			testPartitionFetchedAt(t)),
		Component: componentForTopic(topic),
		Score:     score,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Topic: topic, Value: body}
}

func headerMsg(t *testing.T, emailID, orgID int64, score int) kafkaconsumer.Message {
	t.Helper()
	ft := testPartitionFetchedAt(t)
	body, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID:   emailID,
		OrgID:     orgID,
		FetchedAt: ft,
		Component: contracts.ComponentHeader,
		Score:     score,
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

	emailID, orgID := int64(42), int64(1)

	// Three scores arrive before the plan.
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 72)))
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 85)))
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
	assert.Equal(t, out.InternalID, out.Meta.EmailID)
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

	emailID, orgID := int64(7), int64(1)

	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 60)))
	require.Equal(t, 1, pub.count())

	// A redelivered duplicate of an already-completed email arrives — it
	// hits an already-deleted key, so it just re-stores fresh state but
	// the plan is no longer present (key was DEL'd). It must NOT publish.
	require.NoError(t, a.Handle(ctx, headerMsg(t, emailID, orgID, 60)))
	assert.Equal(t, 1, pub.count(), "duplicate after DEL must not republish")
}

func TestHandle_PublishFailure_ReleasesLockForRetry(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{failNext: 1}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := int64(99), int64(1)

	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID, contracts.TopicScoresURL)))
	err := a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 80))
	require.Error(t, err, "publish failure must surface as error so offset is not committed")
	assert.Equal(t, 0, pub.count())

	assert.False(t, store.nxHeld(publishLockKey(orgID, emailID)), "publish NX lock must be released after failure")

	// Redelivery succeeds.
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 80)))
	assert.Equal(t, 1, pub.count())
}

func TestSweeper_TimeoutEmitsPartial(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	pub := &recorderPublisher{}
	a := newAgg(t, store, pub)
	ctx := context.Background()

	emailID, orgID := int64(123), int64(1)

	// Pretend the first message arrived ≥ 30 s ago.
	a.now = func() time.Time { return time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC) }
	require.NoError(t, a.Handle(ctx, planMsg(t, emailID, orgID,
		contracts.TopicScoresURL, contracts.TopicScoresHeader,
	)))
	require.NoError(t, a.Handle(ctx, envelopeMsg(t, contracts.TopicScoresURL, emailID, orgID, 50)))
	// Header never arrives.

	require.Equal(t, 0, pub.count())

	// Advance time and run a sweeper tick.
	a.now = func() time.Time { return time.Date(2026, 5, 3, 10, 0, 31, 0, time.UTC) }
	NewSweeper(a).tick(ctx)

	require.Equal(t, 1, pub.count(), "timeout must trigger a partial emit")
	var out contracts.EmailsScored
	require.NoError(t, json.Unmarshal(pub.messages[0], &out))
	assert.True(t, out.TimeoutTriggered)
	assert.True(t, out.PartialAnalysis)
	assert.Equal(t, []string{contracts.TopicScoresHeader}, out.MissingComponents)
}

func TestPackager_FlatHeaderShapeForwardedRaw(t *testing.T) {
	t.Parallel()

	headerBody, err := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID:   1,
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
	out, err := packageState(1, 1, state, time.Now().UTC(), false)
	require.NoError(t, err)
	require.NotNil(t, out.HeaderScore)
	assert.Equal(t, 85, *out.HeaderScore)
	// Raw body is forwarded byte-for-byte.
	assert.JSONEq(t, string(headerBody), string(out.ComponentDetails.Header))
}

func TestExtractIDs_EnvelopeAndFlatShapes(t *testing.T) {
	t.Parallel()

	envBody, _ := json.Marshal(contracts.ScoreEnvelope{
		Meta: contracts.NewMeta(11, 22), Component: "url", Score: 50,
	})
	hdrBody, _ := json.Marshal(contracts.ScoresHeaderMessage{
		EmailID: 33, OrgID: 44, Component: "header", Score: 70,
	})

	eid, oid, err := extractIDs(envBody)
	require.NoError(t, err)
	assert.Equal(t, int64(11), eid)
	assert.Equal(t, int64(22), oid)

	eid, oid, err = extractIDs(hdrBody)
	require.NoError(t, err)
	assert.Equal(t, int64(33), eid)
	assert.Equal(t, int64(44), oid)
}

func TestKeyForOrgEmail_Deterministic(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "aggregator:1:42", keyForOrgEmail(1, 42))
	assert.Equal(t, "aggregator:2:"+strconv.FormatInt(123456789, 10), keyForOrgEmail(2, 123456789))
}

func TestIsEmailAggregatorKey(t *testing.T) {
	t.Parallel()
	assert.True(t, isEmailAggregatorKey(keyForOrgEmail(1, 42)))
	assert.False(t, isEmailAggregatorKey(publishLockKey(1, 42)), "publish lock keys must not be swept as buckets")
}

func TestParseAggregatorBucketKey(t *testing.T) {
	t.Parallel()
	o, e, ok := parseAggregatorBucketKey("aggregator:7:99")
	require.True(t, ok)
	assert.Equal(t, int64(7), o)
	assert.Equal(t, int64(99), e)

	_, _, bad := parseAggregatorBucketKey("aggregator:notnum:1")
	assert.False(t, bad)

	_, _, lock := parseAggregatorBucketKey("aggregator:publock:7:99")
	assert.False(t, lock)

	_, _, legacy := parseAggregatorBucketKey("aggregator:42")
	assert.False(t, legacy, "legacy email-only keys must not parse")
}
