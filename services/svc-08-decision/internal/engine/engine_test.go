package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-08-decision/internal/campaign"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/persist"
	"github.com/saif/cybersiren/services/svc-08-decision/internal/rules"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaconsumer "github.com/saif/cybersiren/shared/kafka/consumer"
)

type fakeRules struct {
	rules []rules.CachedRule
	err   error
}

func (f fakeRules) Get(_ context.Context, _ int64) ([]rules.CachedRule, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rules, nil
}

type fakeSimhash struct{}

func (fakeSimhash) Compute(string) (uint64, bool) { return 0, false }
func (fakeSimhash) Lookup(context.Context, int64, uint64) (campaign.Match, bool, error) {
	return campaign.Match{}, false, nil
}
func (fakeSimhash) Store(context.Context, int64, int64, uint64, string) error { return nil }

type fakeWriter struct {
	out       persist.Output
	err       error
	lastInput persist.Input
	writes    int
}

func (f *fakeWriter) Write(_ context.Context, in persist.Input) (persist.Output, error) {
	f.lastInput = in
	f.writes++
	return f.out, f.err
}

func (f *fakeWriter) GetCampaignHistory(context.Context, int64, string) (*persist.CampaignHistory, error) {
	return nil, nil
}

type publishedRecord struct {
	key     []byte
	value   []byte
	retries int
}

type fakePublisher struct {
	records []publishedRecord
}

func (f *fakePublisher) Publish(_ context.Context, key, value []byte, retries int) error {
	f.records = append(f.records, publishedRecord{
		key:     append([]byte(nil), key...),
		value:   append([]byte(nil), value...),
		retries: retries,
	})
	return nil
}

func makeScoredMessage(t *testing.T, internalID int64, emailID string) kafkaconsumer.Message {
	t.Helper()
	fetched := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	url := 77
	body, err := json.Marshal(contracts.EmailsScored{
		Meta:       contracts.NewMetaWithFetched(emailID, 7, fetched),
		InternalID: internalID,
		FetchedAt:  fetched,
		URLScore:   &url,
	})
	require.NoError(t, err)
	return kafkaconsumer.Message{Value: body}
}

func TestDecodeScored_AllowsDistinctInternalAndMetaEmailID(t *testing.T) {
	t.Parallel()
	msg := makeScoredMessage(t, 2001, "e1001")
	got, err := decodeScored(msg.Value)
	require.NoError(t, err)
	require.Equal(t, int64(2001), got.InternalID)
	require.Equal(t, "e1001", got.Meta.EmailID)
}

// A scored message with internal_id<=0 is unaddressable poison (it should have
// been dropped at svc-07's producer). decodeScored must reject it with the
// errUnresolvedInternalID sentinel so Handle can log it loudly — yet still
// commit the offset (a NACK would wedge the partition forever). Finding #8.
func TestDecodeScored_RejectsUnresolvedInternalID(t *testing.T) {
	t.Parallel()
	_, err := decodeScored(makeScoredMessage(t, 0, "e0").Value)
	require.Error(t, err)
	require.ErrorIs(t, err, errUnresolvedInternalID)

	_, err = decodeScored(makeScoredMessage(t, -1, "eneg").Value)
	require.ErrorIs(t, err, errUnresolvedInternalID)
}

func TestHandle_UnresolvedInternalID_CommitsWithoutWritingVerdict(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		fakeRules{},
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	// Poison: internal_id=0. Handle must commit the offset (nil) but write no
	// verdict and publish nothing — the silent-data-loss path is now loud-but-safe.
	err := eng.Handle(context.Background(), makeScoredMessage(t, 0, "e0"))
	require.NoError(t, err, "poison must commit the offset, not NACK")
	require.Equal(t, 0, writer.writes, "no verdict row may be written for an unaddressable message")
	require.Len(t, pub.records, 0, "nothing may be published for an unaddressable message")
}

func TestHandle_DegradesWhenRulesUnavailable(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{out: persist.Output{CampaignID: 17, VerdictID: 44, EmailCount: 1}}
	pub := &fakePublisher{}
	eng := New(
		Config{PublishRetryAttempts: 2},
		nil, // explicit: unavailable rules cache should degrade, not panic
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	err := eng.Handle(context.Background(), makeScoredMessage(t, 1001, "e1001"))
	require.NoError(t, err)
	require.Equal(t, 1, writer.writes)
	require.Equal(t, VerdictSourceRule, writer.lastInput.VerdictSource)
	require.Len(t, pub.records, 1)
	require.Equal(t, 2, pub.records[0].retries)
}

func TestHandle_UsesStoredKafkaWireOnDedupeReplay(t *testing.T) {
	t.Parallel()
	stored := []byte(`{"verdict_label":"benign","risk_score":11}`)
	writer := &fakeWriter{out: persist.Output{
		DedupeSkip:       true,
		CampaignID:       17,
		VerdictID:        44,
		EmailCount:       3,
		KafkaVerdictWire: stored,
	}}
	pub := &fakePublisher{}
	eng := New(
		Config{},
		fakeRules{err: errors.New("cache unavailable")},
		fakeSimhash{},
		writer,
		pub,
		nil,
		zerolog.Nop(),
	)

	err := eng.Handle(context.Background(), makeScoredMessage(t, 3001, "e3001"))
	require.NoError(t, err)
	require.Len(t, pub.records, 1)
	require.JSONEq(t, string(stored), string(pub.records[0].value))
}
