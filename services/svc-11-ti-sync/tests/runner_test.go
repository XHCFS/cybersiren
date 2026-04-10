package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

func TestRunnerSyncAll_AllFeedsSucceed(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "phishtank", feedID: 1, indicators: []ti.TIIndicator{testIndicator(1, "https://a.example")}},
		&mockFeed{name: "openphish", feedID: 2, indicators: []ti.TIIndicator{testIndicator(2, "https://b.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
	assert.Len(t, repo.upsertCalls, 2)
	assert.ElementsMatch(t, []int64{1, 2}, repo.upsertCalls)
	assert.ElementsMatch(t, []int64{1, 2}, repo.updateFetchedCalls)
}

func TestRunnerSyncAll_OneFeedFetchFailsPartialSuccess(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "phishtank", feedID: 1, fetchErr: errors.New("fetch failed")},
		&mockFeed{name: "openphish", feedID: 2, indicators: []ti.TIIndicator{testIndicator(2, "https://b.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	assert.Len(t, repo.upsertCalls, 1)
	assert.Equal(t, int64(2), repo.upsertCalls[0])
	assert.ElementsMatch(t, []int64{1, 2}, repo.updateFetchedCalls)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_AllFeedsFailReturnsError(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "phishtank", feedID: 1, fetchErr: errors.New("fetch failed")},
		&mockFeed{name: "openphish", feedID: 2, fetchErr: errors.New("fetch failed")},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "all 2 feeds failed")
	assert.False(t, cache.refreshCalled)
	assert.False(t, repo.refreshMVCalled)
	assert.ElementsMatch(t, []int64{1, 2}, repo.updateFetchedCalls)
}

func TestRunnerSyncAll_UpsertErrorOnOneFeedContinues(t *testing.T) {
	repo := &mockRepo{
		upsertErrByFeed: map[int64]error{
			1: errors.New("upsert failed"),
		},
	}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "phishtank", feedID: 1, indicators: []ti.TIIndicator{testIndicator(1, "https://a.example")}},
		&mockFeed{name: "openphish", feedID: 2, indicators: []ti.TIIndicator{testIndicator(2, "https://b.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	assert.Len(t, repo.upsertCalls, 2)
	assert.ElementsMatch(t, []int64{1, 2}, repo.upsertCalls)
	assert.ElementsMatch(t, []int64{1, 2}, repo.updateFetchedCalls)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_CacheRefreshErrorIsBestEffort(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{refreshErr: errors.New("cache unavailable")}
	feeds := []ti.Feed{
		&mockFeed{name: "urlhaus", feedID: 3, indicators: []ti.TIIndicator{testIndicator(3, "https://c.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_MaterializedViewRefreshErrorReturnsError(t *testing.T) {
	mvErr := errors.New("mv refresh failed")
	repo := &mockRepo{refreshMVErr: mvErr}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "threatfox", feedID: 4, indicators: []ti.TIIndicator{testIndicator(4, "https://d.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, mvErr)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_UpdateLastFetchedCalledForEveryFeed(t *testing.T) {
	repo := &mockRepo{
		upsertErrByFeed: map[int64]error{
			3: errors.New("upsert failed"),
		},
	}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{name: "phishtank", feedID: 1, fetchErr: errors.New("fetch failed")},
		&mockFeed{name: "openphish", feedID: 2, indicators: []ti.TIIndicator{testIndicator(2, "https://b.example")}},
		&mockFeed{name: "urlhaus", feedID: 3, indicators: []ti.TIIndicator{testIndicator(3, "https://c.example")}},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	assert.Len(t, repo.updateFetchedCalls, 3)
	assert.ElementsMatch(t, []int64{1, 2, 3}, repo.updateFetchedCalls)
}

func TestRunnerSyncAll_HashIndicatorsBypassTIUpsertAndRefreshHashCache(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{
			name:   "threatfox",
			feedID: 7,
			indicators: []ti.TIIndicator{
				testIndicator(7, "https://evil.example"),
				testHashIndicator(7, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			},
		},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	require.Len(t, repo.upsertIndicatorBatches, 1)
	require.Len(t, repo.upsertIndicatorBatches[0], 1)
	assert.Equal(t, ti.URLIndicatorType, string(repo.upsertIndicatorBatches[0][0].IndicatorType))
	require.Len(t, repo.malwareHashBatches, 1)
	require.Len(t, repo.malwareHashBatches[0], 1)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", repo.malwareHashBatches[0][0].SHA256)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_HashUpsertAndHashCacheErrorsAreBestEffort(t *testing.T) {
	repo := &mockRepo{malwareHashErr: errors.New("hash upsert failed")}
	cache := &mockCache{hashRefreshErr: errors.New("hash cache unavailable")}
	feeds := []ti.Feed{
		&mockFeed{
			name:       "malwarebazaar",
			feedID:     8,
			indicators: []ti.TIIndicator{testHashIndicator(8, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	// Hash-only feeds treat a hash upsert failure as fatal because zero
	// data was persisted, so SyncAll reports all feeds failed.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all 1 feeds failed")
	assert.Empty(t, repo.upsertIndicatorBatches[0])
	assert.Len(t, repo.malwareHashBatches, 1)
	// Deactivation runs after hash upsert; since hash upsert failed and
	// the feed is hash-only, the loop continues before reaching deactivation.
	assert.Empty(t, repo.deactivateCalls)
	// Cache and MV refresh are skipped when all feeds fail.
	assert.False(t, cache.refreshCalled)
	assert.False(t, cache.hashRefreshCalled)
	assert.False(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_MixedFeedHashUpsertFailureIsBestEffort(t *testing.T) {
	repo := &mockRepo{malwareHashErr: errors.New("hash upsert failed")}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{
			name:   "threatfox",
			feedID: 7,
			indicators: []ti.TIIndicator{
				testIndicator(7, "https://evil.example"),
				testHashIndicator(7, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			},
		},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	// Mixed feeds have non-hash indicators persisted, so hash upsert failure
	// is best-effort — SyncAll should still succeed.
	require.NoError(t, err)
	assert.Len(t, repo.upsertIndicatorBatches, 1)
	assert.Len(t, repo.upsertIndicatorBatches[0], 1, "only non-hash indicator should be upserted")
	assert.Len(t, repo.malwareHashBatches, 1)
	assert.True(t, cache.refreshCalled)
	assert.True(t, cache.hashRefreshCalled)
	assert.True(t, repo.refreshMVCalled)
}

func TestRunnerSyncAll_HashOnlyFeedCallsDeactivateStaleIndicators(t *testing.T) {
	repo := &mockRepo{deactivateResult: 3}
	cache := &mockCache{}
	feeds := []ti.Feed{
		&mockFeed{
			name:       "malwarebazaar",
			feedID:     8,
			indicators: []ti.TIIndicator{testHashIndicator(8, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")},
		},
	}

	runner := ti.NewRunner(feeds, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(context.Background())

	require.NoError(t, err)
	// Hash-only feeds should still call DeactivateStaleIndicators.
	require.Len(t, repo.deactivateCalls, 1)
	assert.Equal(t, int64(8), repo.deactivateCalls[0])
	assert.True(t, cache.hashRefreshCalled)
}

func TestRunnerSyncAll_ContextCancellationSkipsRemainingFeeds(t *testing.T) {
	repo := &mockRepo{}
	cache := &mockCache{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstFeed := &mockFeed{name: "phishtank", feedID: 1, indicators: []ti.TIIndicator{testIndicator(1, "https://a.example")}}
	secondFeed := &mockFeed{
		name:   "openphish",
		feedID: 2,
		onFetch: func(ctx context.Context) ([]ti.TIIndicator, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	thirdFeed := &mockFeed{name: "urlhaus", feedID: 3, indicators: []ti.TIIndicator{testIndicator(3, "https://c.example")}}

	runner := ti.NewRunner([]ti.Feed{firstFeed, secondFeed, thirdFeed}, repo, cache, zerolog.Nop(), prometheus.NewRegistry())
	err := runner.SyncAll(ctx)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, thirdFeed.fetchCalls)
	assert.ElementsMatch(t, []int64{1, 2}, repo.updateFetchedCalls)
	assert.False(t, cache.refreshCalled)
	assert.False(t, repo.refreshMVCalled)
}

type mockFeed struct {
	name       string
	feedID     int64
	indicators []ti.TIIndicator
	fetchErr   error
	onFetch    func(ctx context.Context) ([]ti.TIIndicator, error)
	fetchCalls int
}

func (m *mockFeed) Name() string {
	if m == nil {
		return ""
	}
	return m.name
}

func (m *mockFeed) FeedID() int64 {
	if m == nil {
		return 0
	}
	return m.feedID
}

func (m *mockFeed) Fetch(ctx context.Context) ([]ti.TIIndicator, error) {
	m.fetchCalls++
	if m.onFetch != nil {
		return m.onFetch(ctx)
	}
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}

	return append([]ti.TIIndicator(nil), m.indicators...), nil
}

type mockRepo struct {
	upsertCalled           bool
	upsertErr              error
	upsertErrByFeed        map[int64]error
	upsertCalls            []int64
	upsertIndicatorBatches [][]repository.TIIndicator
	malwareHashBatches     [][]repository.MalwareHash
	malwareHashErr         error
	deactivateCalls        []int64
	deactivateResult       int
	deactivateErr          error
	updateFetchedCalls     []int64
	refreshMVCalled        bool
	refreshMVErr           error
}

func (m *mockRepo) BulkUpsertIndicators(_ context.Context, indicators []repository.TIIndicator) (repository.UpsertResult, error) {
	m.upsertCalled = true

	feedID := int64(0)
	if len(indicators) > 0 {
		feedID = indicators[0].FeedID
	}
	m.upsertCalls = append(m.upsertCalls, feedID)
	m.upsertIndicatorBatches = append(m.upsertIndicatorBatches, append([]repository.TIIndicator(nil), indicators...))

	if m.upsertErrByFeed != nil {
		if upsertErr, ok := m.upsertErrByFeed[feedID]; ok && upsertErr != nil {
			return repository.UpsertResult{}, upsertErr
		}
	}
	if m.upsertErr != nil {
		return repository.UpsertResult{}, m.upsertErr
	}

	return repository.UpsertResult{Inserted: len(indicators)}, nil
}

func (m *mockRepo) UpdateFeedLastFetched(_ context.Context, feedID int64) error {
	m.updateFetchedCalls = append(m.updateFetchedCalls, feedID)
	return nil
}

func (m *mockRepo) DeactivateStaleIndicators(_ context.Context, feedID int64) (int, error) {
	m.deactivateCalls = append(m.deactivateCalls, feedID)
	if m.deactivateErr != nil {
		return 0, m.deactivateErr
	}
	return m.deactivateResult, nil
}

func (m *mockRepo) ListActiveDomainIndicators(_ context.Context) ([]repository.DomainIndicator, error) {
	return nil, nil
}

func (m *mockRepo) BulkUpsertMalwareHashes(_ context.Context, hashes []repository.MalwareHash) (repository.UpsertResult, error) {
	m.malwareHashBatches = append(m.malwareHashBatches, append([]repository.MalwareHash(nil), hashes...))
	if m.malwareHashErr != nil {
		return repository.UpsertResult{}, m.malwareHashErr
	}
	return repository.UpsertResult{Inserted: len(hashes)}, nil
}

func (m *mockRepo) ListMaliciousHashes(_ context.Context) ([]repository.MaliciousHash, error) {
	return nil, nil
}

func (m *mockRepo) RefreshAllMaterializedViews(_ context.Context) error {
	m.refreshMVCalled = true
	return m.refreshMVErr
}

type mockCache struct {
	refreshCalled     bool
	refreshErr        error
	hashRefreshCalled bool
	hashRefreshErr    error
}

func (m *mockCache) RefreshDomainCache(_ context.Context) error {
	m.refreshCalled = true
	return m.refreshErr
}

func (m *mockCache) RefreshHashCache(_ context.Context) error {
	m.hashRefreshCalled = true
	return m.hashRefreshErr
}

func (m *mockCache) IsBlocklisted(_ context.Context, _ string) (bool, int, string, error) {
	return false, 0, "", nil
}

func testIndicator(feedID int64, indicatorValue string) ti.TIIndicator {
	return ti.TIIndicator{
		FeedID:         feedID,
		IndicatorType:  ti.URLIndicatorType,
		IndicatorValue: indicatorValue,
		ThreatType:     "phishing",
		ThreatTags:     []string{"test"},
		RiskScore:      80,
		Confidence:     0.9,
		SourceID:       "source",
	}
}

func testHashIndicator(feedID int64, sha256 string) ti.TIIndicator {
	return ti.TIIndicator{
		FeedID:         feedID,
		IndicatorType:  ti.HashIndicatorType,
		IndicatorValue: sha256,
		ThreatType:     "malware",
		ThreatTags:     []string{"test"},
		RiskScore:      90,
		Confidence:     0.95,
		SourceID:       sha256,
	}
}
