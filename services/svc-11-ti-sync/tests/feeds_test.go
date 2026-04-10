package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
)

func TestPhishTankFeed_APIKeyMissing(t *testing.T) {
	client := newTestHTTPClient()
	_, err := tifeeds.NewPhishTankFeed(1, &config.Config{}, client, zerolog.Nop())
	require.Error(t, err)
	assert.ErrorIs(t, err, ti.ErrPhishTankKeyMissing)
}

func TestPhishTankFeed_APIKeyFromConfig(t *testing.T) {
	client := newTestHTTPClient()
	feed, err := tifeeds.NewPhishTankFeed(10, &config.Config{FeedPhishTankAPIKey: "config-phishtank-key"}, client, zerolog.Nop())
	require.NoError(t, err)

	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	feed.URLTemplate = server.URL + "/data/{api_key}/online-valid.json"

	indicators, fetchErr := feed.Fetch(context.Background())
	require.NoError(t, fetchErr)
	assert.Empty(t, indicators)
	assert.Contains(t, requestedPath, "/data/config-phishtank-key/online-valid.json")
}

func TestPhishTankFeed_Fetch(t *testing.T) {
	type testCase struct {
		name          string
		statusCode    int
		body          string
		expectErr     bool
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	testCases := []testCase{
		{
			name:        "success verified only",
			statusCode:  http.StatusOK,
			body:        `[{"phish_id":"1001","url":"HTTP://Example.com/login","verified":true},{"phish_id":"1002","url":"https://skip.example","verified":false}]`,
			expectCount: 1,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 1)
				assert.Equal(t, int64(10), indicators[0].FeedID)
				assert.Equal(t, "url", indicators[0].IndicatorType)
				assert.Equal(t, "http://example.com/login", indicators[0].IndicatorValue)
				assert.Equal(t, "phishing", indicators[0].ThreatType)
				assert.Equal(t, []string{"phishtank", "verified"}, indicators[0].ThreatTags)
				assert.Equal(t, 90, indicators[0].RiskScore)
				assert.Equal(t, 0.95, indicators[0].Confidence)
				assert.Equal(t, "1001", indicators[0].SourceID)
				assert.NotEmpty(t, indicators[0].RawMetadata)
			},
		},
		{
			name:        "empty response",
			statusCode:  http.StatusOK,
			body:        `[]`,
			expectCount: 0,
		},
		{
			name:       "http server error",
			statusCode: http.StatusBadGateway,
			body:       `{"error":"upstream"}`,
			expectErr:  true,
		},
		{
			name:       "invalid json",
			statusCode: http.StatusOK,
			body:       `[`,
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			cfg := &config.Config{FeedPhishTankAPIKey: "test-key"}

			var requestedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestedPath = r.URL.Path
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed, err := tifeeds.NewPhishTankFeed(10, cfg, client, zerolog.Nop())
			require.NoError(t, err)
			feed.URLTemplate = server.URL + "/data/{api_key}/online-valid.json"

			indicators, fetchErr := feed.Fetch(context.Background())
			if tc.expectErr {
				require.Error(t, fetchErr)
				assert.Contains(t, fetchErr.Error(), "phishtank:")
				return
			}

			require.NoError(t, fetchErr)
			assert.Contains(t, requestedPath, "/data/test-key/online-valid.json")
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestOpenPhishFeed_Fetch(t *testing.T) {
	type testCase struct {
		name          string
		statusCode    int
		body          string
		expectErr     bool
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	testCases := []testCase{
		{
			name:        "success with blank and invalid lines",
			statusCode:  http.StatusOK,
			body:        "https://A.example/login\n\nhttp://b.example/path\nhttp://\n",
			expectCount: 2,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 2)
				assert.Equal(t, "https://a.example/login", indicators[0].IndicatorValue)
				assert.Equal(t, []string{"openphish"}, indicators[0].ThreatTags)
				assert.Equal(t, 85, indicators[0].RiskScore)
				assert.Equal(t, 0.80, indicators[0].Confidence)

				h := sha256.Sum256([]byte("https://a.example/login"))
				assert.Equal(t, hex.EncodeToString(h[:]), indicators[0].SourceID)
			},
		},
		{
			name:        "empty response",
			statusCode:  http.StatusOK,
			body:        "",
			expectCount: 0,
		},
		{
			name:       "http server error",
			statusCode: http.StatusServiceUnavailable,
			body:       "temporary outage",
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed := tifeeds.NewOpenPhishFeed(11, client, zerolog.Nop())
			feed.URL = server.URL

			indicators, err := feed.Fetch(context.Background())
			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "openphish:")
				return
			}

			require.NoError(t, err)
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestURLhausFeed_Fetch(t *testing.T) {
	type testCase struct {
		name          string
		statusCode    int
		body          string
		expectErr     bool
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	testCases := []testCase{
		{
			name:       "success applies threat and offline filters",
			statusCode: http.StatusOK,
			body: strings.Join([]string{
				"# comment header",
				"id,url,url_status,threat,tags",
				"1,https://good1.example,online,phishing,phish,credential",
				"2,https://good2.example,online,malware_download,ransomware",
				"3,https://skip-offline.example,offline,phishing,tag",
				"4,https://skip-threat.example,online,benign,tag",
				"5,http://,online,phishing,tag",
			}, "\n"),
			expectCount: 2,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 2)
				assert.Equal(t, "1", indicators[0].SourceID)
				assert.Equal(t, "https://good1.example", indicators[0].IndicatorValue)
				assert.Equal(t, "phishing", indicators[0].ThreatType)
				assert.Contains(t, indicators[0].ThreatTags, "urlhaus")
				assert.Equal(t, 80, indicators[0].RiskScore)
				assert.Equal(t, 0.75, indicators[0].Confidence)
				assert.Equal(t, "2", indicators[1].SourceID)
				assert.Equal(t, "https://good2.example", indicators[1].IndicatorValue)
				assert.Equal(t, "malware_download", indicators[1].ThreatType)
			},
		},
		{
			name:        "empty response",
			statusCode:  http.StatusOK,
			body:        "# no data\n# still no data\n",
			expectCount: 0,
		},
		{
			name:       "http server error",
			statusCode: http.StatusBadGateway,
			body:       "error",
			expectErr:  true,
		},
		{
			name:       "invalid csv",
			statusCode: http.StatusOK,
			body:       "id,url,url_status,threat,tags\n\"unclosed",
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed := tifeeds.NewURLhausFeed(12, client, zerolog.Nop())
			feed.URL = server.URL

			indicators, err := feed.Fetch(context.Background())
			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "urlhaus:")
				return
			}

			require.NoError(t, err)
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestThreatFoxFeed_Fetch(t *testing.T) {
	type testCase struct {
		name          string
		statusCode    int
		body          string
		expectErr     bool
		errIs         error
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	testCases := []testCase{
		{
			name:       "success with multi-type indicators",
			statusCode: http.StatusOK,
			body: `{"query_status":"ok","data":[
				{"id":"11","ioc_type":"url","ioc":"https://evil.example/path","threat_type":"phishing","tags":["kit","phish"],"confidence_level":88},
				{"id":"12","ioc_type":"domain","ioc":"evil.example","threat_type":"phishing","tags":["skip"],"confidence_level":55},
				{"id":13,"ioc_type":"url","ioc":"https://high.example","threat_type":"malware","tags":"c2,botnet","confidence_level":150},
				{"id":"14","ioc_type":"ip:port","ioc":"192.0.2.1:443","threat_type":"c2","tags":["botnet"],"confidence_level":70},
				{"id":"15","ioc_type":"sha256_hash","ioc":"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890","threat_type":"malware","tags":["trojan"],"confidence_level":95},
				{"id":"16","ioc_type":"md5_hash","ioc":"d41d8cd98f00b204e9800998ecf8427e","threat_type":"malware","tags":["skip"],"confidence_level":10}
			]}`,
			expectCount: 5,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 5)

				// URL entry.
				assert.Equal(t, "11", indicators[0].SourceID)
				assert.Equal(t, "url", indicators[0].IndicatorType)
				assert.Equal(t, "https://evil.example/path", indicators[0].IndicatorValue)
				assert.Equal(t, 88, indicators[0].RiskScore)
				assert.Equal(t, 0.88, indicators[0].Confidence)
				assert.Contains(t, indicators[0].ThreatTags, "threatfox")

				// Domain entry (previously filtered out).
				assert.Equal(t, "12", indicators[1].SourceID)
				assert.Equal(t, "domain", indicators[1].IndicatorType)
				assert.Equal(t, "evil.example", indicators[1].IndicatorValue)
				assert.Equal(t, 55, indicators[1].RiskScore)

				// URL with clamped confidence.
				assert.Equal(t, "13", indicators[2].SourceID)
				assert.Equal(t, "url", indicators[2].IndicatorType)
				assert.Equal(t, 100, indicators[2].RiskScore)
				assert.Equal(t, 1.0, indicators[2].Confidence)
				assert.Equal(t, "malware", indicators[2].ThreatType)

				// IP:port entry.
				assert.Equal(t, "14", indicators[3].SourceID)
				assert.Equal(t, "ip", indicators[3].IndicatorType)
				assert.Equal(t, "192.0.2.1", indicators[3].IndicatorValue)
				assert.Equal(t, 70, indicators[3].RiskScore)
				assert.Contains(t, indicators[3].ThreatTags, "threatfox")

				// Hash entry.
				assert.Equal(t, "15", indicators[4].SourceID)
				assert.Equal(t, ti.HashIndicatorType, indicators[4].IndicatorType)
				assert.Equal(t, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", indicators[4].IndicatorValue)
				assert.Equal(t, 95, indicators[4].RiskScore)
				assert.Contains(t, indicators[4].ThreatTags, "threatfox")
			},
		},
		{
			name:        "empty response",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"ok","data":[]}`,
			expectCount: 0,
		},
		{
			name:       "query status error",
			statusCode: http.StatusOK,
			body:       `{"query_status":"error","data":[]}`,
			expectErr:  true,
			errIs:      ti.ErrThreatFoxAPIError,
		},
		{
			name:       "http server error",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error":"upstream"}`,
			expectErr:  true,
		},
		{
			name:       "invalid json",
			statusCode: http.StatusOK,
			body:       `{`,
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			var requestMethod string
			var contentType string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestMethod = r.Method
				contentType = r.Header.Get("Content-Type")
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed := tifeeds.NewThreatFoxFeed(13, &config.Config{}, client, zerolog.Nop())
			feed.URL = server.URL

			indicators, err := feed.Fetch(context.Background())
			assert.Equal(t, http.MethodPost, requestMethod)
			assert.Contains(t, strings.ToLower(contentType), "application/json")

			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "threatfox:")
				if tc.errIs != nil {
					assert.True(t, errors.Is(err, tc.errIs))
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestMalwareBazaarFeed_Fetch(t *testing.T) {
	type testCase struct {
		name          string
		statusCode    int
		body          string
		expectErr     bool
		errIs         error
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	sha256Valid := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	testCases := []testCase{
		{
			name:       "success parses sha256 hashes",
			statusCode: http.StatusOK,
			body: fmt.Sprintf(`{"query_status":"ok","data":[
				{"sha256_hash":"%s","md5_hash":"d41d8cd98f00b204e9800998ecf8427e","sha1_hash":"da39a3ee5e6b4b0d3255bfef95601890afd80709","file_type":"exe","signature":"AgentTesla","tags":["stealer","rat"],"reporter":"abuse_ch"},
				{"sha256_hash":"","md5_hash":"skip","sha1_hash":"skip","file_type":"dll","signature":"","tags":null,"reporter":"someone"}
			]}`, sha256Valid),
			expectCount: 1,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 1)
				ind := indicators[0]
				assert.Equal(t, ti.HashIndicatorType, ind.IndicatorType)
				assert.Equal(t, sha256Valid, ind.IndicatorValue)
				assert.Equal(t, 90, ind.RiskScore)
				assert.Equal(t, 0.95, ind.Confidence)
				assert.Equal(t, "AgentTesla", ind.ThreatType)
				assert.Contains(t, ind.ThreatTags, "malwarebazaar")
				assert.Contains(t, ind.ThreatTags, "stealer")
				assert.Contains(t, ind.ThreatTags, "rat")
				assert.Contains(t, ind.ThreatTags, "exe")
				// Verify no duplicate tags (file_type should not appear twice).
				seen := make(map[string]bool, len(ind.ThreatTags))
				for _, tag := range ind.ThreatTags {
					assert.False(t, seen[tag], "duplicate tag: %s", tag)
					seen[tag] = true
				}
				assert.Equal(t, sha256Valid, ind.SourceID)
				assert.NotEmpty(t, ind.RawMetadata)
			},
		},
		{
			name:        "signature empty defaults to malware",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"ok","data":[{"sha256_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","md5_hash":"","sha1_hash":"","file_type":"pdf","signature":"","tags":[],"reporter":"tester"}]}`,
			expectCount: 1,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				require.Len(t, indicators, 1)
				assert.Equal(t, "malware", indicators[0].ThreatType)
				assert.Contains(t, indicators[0].ThreatTags, "pdf")
			},
		},
		{
			name:        "empty data array",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"ok","data":[]}`,
			expectCount: 0,
		},
		{
			name:        "no_results returns empty success",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"no_results","data":[]}`,
			expectCount: 0,
		},
		{
			name:       "query status error",
			statusCode: http.StatusOK,
			body:       `{"query_status":"illegal_search_value","data":[]}`,
			expectErr:  true,
			errIs:      ti.ErrMalwareBazaarAPIError,
		},
		{
			name:       "http server error",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error":"upstream"}`,
			expectErr:  true,
		},
		{
			name:       "invalid json",
			statusCode: http.StatusOK,
			body:       `{`,
			expectErr:  true,
		},
		{
			name:        "invalid sha256 hash is skipped",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"ok","data":[{"sha256_hash":"not-a-valid-hash","md5_hash":"","sha1_hash":"","file_type":"exe","signature":"test","tags":[],"reporter":"someone"}]}`,
			expectCount: 0,
		},
		{
			name:        "non-hex sha256 hash is skipped",
			statusCode:  http.StatusOK,
			body:        `{"query_status":"ok","data":[{"sha256_hash":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","md5_hash":"","sha1_hash":"","file_type":"exe","signature":"test","tags":[],"reporter":"someone"}]}`,
			expectCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			var requestMethod string
			var contentType string
			var requestBody string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestMethod = r.Method
				contentType = r.Header.Get("Content-Type")
				payload, _ := io.ReadAll(r.Body)
				requestBody = string(payload)
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed, feedErr := tifeeds.NewMalwareBazaarFeed(14, &config.Config{FeedMalwareBazaarAPIKey: "test-key"}, client, zerolog.Nop())
			require.NoError(t, feedErr)
			feed.URL = server.URL

			indicators, err := feed.Fetch(context.Background())
			assert.Equal(t, http.MethodPost, requestMethod)
			assert.Contains(t, strings.ToLower(contentType), "application/x-www-form-urlencoded")
			assert.Contains(t, requestBody, "query=get_recent")

			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "malwarebazaar:")
				if tc.errIs != nil {
					assert.True(t, errors.Is(err, tc.errIs))
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestMalwareBazaarFeed_APIKeyMissing(t *testing.T) {
	client := newTestHTTPClient()
	_, err := tifeeds.NewMalwareBazaarFeed(1, &config.Config{}, client, zerolog.Nop())
	require.Error(t, err)
	assert.ErrorIs(t, err, ti.ErrMalwareBazaarKeyMissing)
}

func TestMalwareBazaarFeed_NilConfigKeyMissing(t *testing.T) {
	client := newTestHTTPClient()
	_, err := tifeeds.NewMalwareBazaarFeed(1, nil, client, zerolog.Nop())
	require.Error(t, err)
	assert.ErrorIs(t, err, ti.ErrMalwareBazaarKeyMissing)
}

func TestThreatFoxFeed_IPv6EdgeCases(t *testing.T) {
	type testCase struct {
		name          string
		body          string
		expectCount   int
		checkResponse func(t *testing.T, indicators []ti.TIIndicator)
	}

	testCases := []testCase{
		{
			name: "bracketed IPv6 with port",
			body: `{"query_status":"ok","data":[
				{"id":"20","ioc_type":"ip:port","ioc":"[2001:db8::1]:443","threat_type":"c2","tags":["bot"],"confidence_level":80}
			]}`,
			expectCount: 1,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				assert.Equal(t, "ip", indicators[0].IndicatorType)
				assert.Equal(t, "2001:db8::1", indicators[0].IndicatorValue)
			},
		},
		{
			name: "bare IPv6 without port",
			body: `{"query_status":"ok","data":[
				{"id":"21","ioc_type":"ip:port","ioc":"2001:db8::1","threat_type":"c2","tags":["bot"],"confidence_level":80}
			]}`,
			expectCount: 1,
			checkResponse: func(t *testing.T, indicators []ti.TIIndicator) {
				assert.Equal(t, "ip", indicators[0].IndicatorType)
				assert.Equal(t, "2001:db8::1", indicators[0].IndicatorValue)
			},
		},
		{
			name: "invalid IP is skipped",
			body: `{"query_status":"ok","data":[
				{"id":"22","ioc_type":"ip:port","ioc":"not.an.ip","threat_type":"c2","tags":[],"confidence_level":50}
			]}`,
			expectCount: 0,
		},
		{
			name: "invalid sha256 hash is skipped",
			body: `{"query_status":"ok","data":[
				{"id":"23","ioc_type":"sha256_hash","ioc":"tooshort","threat_type":"malware","tags":["trojan"],"confidence_level":90}
			]}`,
			expectCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newTestHTTPClient()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			feed := tifeeds.NewThreatFoxFeed(13, &config.Config{}, client, zerolog.Nop())
			feed.URL = server.URL

			indicators, err := feed.Fetch(context.Background())
			require.NoError(t, err)
			assert.Len(t, indicators, tc.expectCount)
			if tc.checkResponse != nil {
				tc.checkResponse(t, indicators)
			}
		})
	}
}

func TestThreatFoxFeed_APIKeyFromConfig(t *testing.T) {
	client := newTestHTTPClient()
	var authHeader string
	var requestBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Auth-Key")
		payload, _ := io.ReadAll(r.Body)
		requestBody = string(payload)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[]}`))
	}))
	defer server.Close()

	feed := tifeeds.NewThreatFoxFeed(99, &config.Config{FeedThreatFoxAPIKey: "config-threatfox-key"}, client, zerolog.Nop())
	feed.URL = server.URL

	indicators, err := feed.Fetch(context.Background())
	require.NoError(t, err)
	assert.Empty(t, indicators)
	assert.Equal(t, "config-threatfox-key", authHeader)
	assert.Contains(t, requestBody, `"auth_key":"config-threatfox-key"`)
}

func newTestHTTPClient() httputil.Client {
	return httputil.NewClient(
		httputil.WithClientRetry(0, 0, 0),
		httputil.WithClientTimeout(2*time.Second),
	)
}
