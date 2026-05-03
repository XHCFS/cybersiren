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

func makeScoredMessage(t *testing.T, internalID, emailID int64) kafkaconsumer.Message {
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
	msg := makeScoredMessage(t, 2001, 1001)
	got, err := decodeScored(msg.Value)
	require.NoError(t, err)
	require.Equal(t, int64(2001), got.InternalID)
	require.Equal(t, int64(1001), got.Meta.EmailID)
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

	err := eng.Handle(context.Background(), makeScoredMessage(t, 1001, 1001))
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

	err := eng.Handle(context.Background(), makeScoredMessage(t, 3001, 3001))
	require.NoError(t, err)
	require.Len(t, pub.records, 1)
	require.JSONEq(t, string(stored), string(pub.records[0].value))
}
