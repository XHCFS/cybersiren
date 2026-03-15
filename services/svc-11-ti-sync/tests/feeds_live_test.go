package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti"
	tifeeds "github.com/saif/cybersiren/services/svc-11-ti-sync/internal/ti/feeds"
	"github.com/saif/cybersiren/shared/config"
	httputil "github.com/saif/cybersiren/shared/http"
	"github.com/saif/cybersiren/shared/normalization"
)

const (
	liveFeedsEnv             = "RUN_LIVE_FEED_TESTS"
	phishTankEnvAPIKey       = "FEED_PHISHTANK_API_KEY"
	phishTankLegacyEnvAPIKey = "CYBERSIREN_FEED_PHISHTANK_API_KEY"
	threatFoxEnvAPIKey       = "FEED_THREATFOX_API_KEY"
	threatFoxLegacyAPIKey    = "CYBERSIREN_FEED_THREATFOX_API_KEY"
	threatFoxDirectAPIKey    = "THREATFOX_API_KEY"
	testDBNameEnv            = "CYBERSIREN_DB__NAME"
	testDBUserEnv            = "CYBERSIREN_DB__USER"
	testDBPasswordEnv        = "CYBERSIREN_DB__PASSWORD"
	testJWTSecretEnv         = "CYBERSIREN_AUTH__JWT_SECRET"
)

func TestLivePhishTankFeed_Fetch(t *testing.T) {
	requireLiveFeedTestsEnabled(t)
	cfg := loadLiveFeedConfig(t)

	apiKey := strings.TrimSpace(cfg.FeedPhishTankAPIKey)
	if apiKey == "" {
		apiKey = firstNonEmptyEnvValue(phishTankEnvAPIKey, phishTankLegacyEnvAPIKey)
	}
	if apiKey == "" {
		t.Skip("set feed_phishtank_api_key in config.yaml or CYBERSIREN_FEED_PHISHTANK_API_KEY to run live PhishTank test")
	}

	client := newLiveHTTPClient()
	cfg.FeedPhishTankAPIKey = apiKey
	feed, err := tifeeds.NewPhishTankFeed(1001, cfg, client, zerolog.Nop())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	indicators, fetchErr := feed.Fetch(ctx)
	require.NoError(t, fetchErr)
	require.NotEmpty(t, indicators)
	assertLiveIndicatorsSanity(t, indicators)
}

func TestLiveOpenPhishFeed_Fetch(t *testing.T) {
	requireLiveFeedTestsEnabled(t)

	client := newLiveHTTPClient()
	feed := tifeeds.NewOpenPhishFeed(1002, client, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	indicators, err := feed.Fetch(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, indicators)
	assertLiveIndicatorsSanity(t, indicators)
}

func TestLiveURLhausFeed_Fetch(t *testing.T) {
	requireLiveFeedTestsEnabled(t)

	client := newLiveHTTPClient()
	feed := tifeeds.NewURLhausFeed(1003, client, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	indicators, err := feed.Fetch(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, indicators)
	assertLiveIndicatorsSanity(t, indicators)
}

func TestLiveThreatFoxFeed_Fetch(t *testing.T) {
	requireLiveFeedTestsEnabled(t)
	cfg := loadLiveFeedConfig(t)

	apiKey := strings.TrimSpace(cfg.FeedThreatFoxAPIKey)
	if apiKey == "" {
		apiKey = firstNonEmptyEnvValue(threatFoxEnvAPIKey, threatFoxLegacyAPIKey, threatFoxDirectAPIKey)
	}
	if apiKey == "" {
		t.Skip("set feed_threatfox_api_key in config.yaml or CYBERSIREN_FEED_THREATFOX_API_KEY to run live ThreatFox test")
	}

	client := newLiveHTTPClient()
	cfg.FeedThreatFoxAPIKey = apiKey
	feed := tifeeds.NewThreatFoxFeed(1004, cfg, client, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	indicators, err := feed.Fetch(ctx)
	if err != nil {
		errText := strings.ToLower(err.Error())
		if strings.Contains(errText, "status=401") || strings.Contains(errText, "unauthorized") {
			t.Skipf("ThreatFox live endpoint requires auth or blocks this environment: %v", err)
		}
	}
	require.NoError(t, err)
	assertLiveIndicatorsSanity(t, indicators)
}

func requireLiveFeedTestsEnabled(t *testing.T) {
	t.Helper()
	if err := ensureLiveTestEnvLoaded(); err != nil {
		t.Fatalf("failed to load .env for live feed tests: %v", err)
	}

	if strings.TrimSpace(os.Getenv(liveFeedsEnv)) != "1" {
		t.Skip("live feed tests disabled; set RUN_LIVE_FEED_TESTS=1 in env or .env to execute real network pulls")
	}
}

func newLiveHTTPClient() httputil.Client {
	return httputil.NewClient(
		httputil.WithClientTimeout(40*time.Second),
		httputil.WithClientRetry(1, 500*time.Millisecond, 3*time.Second),
	)
}

func assertLiveIndicatorsSanity(t *testing.T, indicators []ti.TIIndicator) {
	t.Helper()

	for i, indicator := range indicators {
		if i >= 25 {
			break
		}
		assert.Equal(t, ti.URLIndicatorType, indicator.IndicatorType)
		assert.NotEmpty(t, strings.TrimSpace(indicator.IndicatorValue))
		assert.True(t, normalization.IsURL(indicator.IndicatorValue))
		assert.GreaterOrEqual(t, indicator.RiskScore, 0)
		assert.LessOrEqual(t, indicator.RiskScore, 100)
		assert.GreaterOrEqual(t, indicator.Confidence, 0.0)
		assert.LessOrEqual(t, indicator.Confidence, 1.0)
	}
}

func firstNonEmptyEnvValue(envVars ...string) string {
	for _, envVar := range envVars {
		value := strings.TrimSpace(os.Getenv(envVar))
		if value != "" {
			return value
		}
	}

	return ""
}

func loadLiveFeedConfig(t *testing.T) *config.Config {
	t.Helper()

	setDefaultEnvForTest(t, testDBNameEnv, "live_test_db")
	setDefaultEnvForTest(t, testDBUserEnv, "live_test_user")
	setDefaultEnvForTest(t, testDBPasswordEnv, "live_test_password")
	setDefaultEnvForTest(t, testJWTSecretEnv, "live-test-jwt-secret")

	cfg, err := config.Load()
	require.NoError(t, err)

	return cfg
}

func setDefaultEnvForTest(t *testing.T, key, fallback string) {
	t.Helper()

	if strings.TrimSpace(os.Getenv(key)) == "" {
		t.Setenv(key, fallback)
	}
}
