package main

// ═══════════════════════════════════════════════════════════════════════════════
// svc-03 URL-analysis demo — HTTP handler test battery
//
// Test groups:
//
//   Unit (pure functions, no network):
//     TestClassifyLabel             – all classification rule paths
//
//   Handler (httptest, fake deps, no network):
//     TestScanHandler_MissingURL        – empty url → 400
//     TestScanHandler_InvalidJSON       – malformed body → 400
//     TestScanHandler_NilScorer         – Layer-2 disabled; label from ML/TI only
//     TestScanHandler_TIMatchSkipsL2    – TI hit → scorer.Score never called
//     TestScanHandler_TIMissCallsL2     – TI miss → scorer.Score called; resp has ML fields
//     TestScanHandler_L2PhishingBoosts  – fusion verdict "phishing" overrides clean ML score
//     TestScanHandler_L2ErrorFailOpen   – scorer error → fail-open, label falls back to ML
//     TestScanHandler_DegradedFlag      – neutral score (50/0.5) sets degraded=true
//     TestScanHandler_ConcurrentSafe    – 50 parallel requests pass the -race detector
// ═══════════════════════════════════════════════════════════════════════════════

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/saif/cybersiren/internal/phishing"
	urlpkg "github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
	sharedhttp "github.com/saif/cybersiren/shared/http"
)

// ─── fake dependencies ────────────────────────────────────────────────────────

type fakeModel struct {
	score  int
	prob   float64
	routed bool
	reason string
	err    error
}

func (f *fakeModel) PredictWithRoute(_ context.Context, _ string) (int, float64, bool, string, error) {
	return f.score, f.prob, f.routed, f.reason, f.err
}

type fakeTI struct {
	result urlpkg.TIResult
	err    error
}

func (f *fakeTI) Check(_ context.Context, _ string) (urlpkg.TIResult, error) {
	return f.result, f.err
}

type fakeScorer struct {
	mu     sync.Mutex
	result phishing.Result
	err    error
	calls  int
}

func (f *fakeScorer) Score(_ context.Context, _ string) (phishing.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.result, f.err
}

func (f *fakeScorer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// ─── test helpers ─────────────────────────────────────────────────────────────

func newTestEngine(model urlPredictor, ti tiLookup, scorer phishingScorer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := sharedhttp.NewServer()
	srv.POST("/scan", scanHandler(model, ti, scorer, nil, zerolog.Nop()))
	return srv.Engine()
}

// doScan fires a POST /scan and returns the recorder + decoded data payload.
func doScan(t *testing.T, engine *gin.Engine, rawURL string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	body := `{"url":` + jsonStr(rawURL) + `}`
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&envelope)
	return w, envelope.Data
}

// doScanRaw fires POST /scan with an arbitrary body (for malformed-JSON tests).
func doScanRaw(t *testing.T, engine *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ─── Unit: classifyLabel ──────────────────────────────────────────────────────

func TestClassifyLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		score     int
		ti        urlpkg.TIResult
		routed    bool
		mlVerdict string
		want      string
	}{
		{
			name:  "TI high risk → phishing",
			score: 10, ti: urlpkg.TIResult{Matched: true, RiskScore: 90},
			want: "phishing",
		},
		{
			name:  "TI match low risk → not phishing (TI risk < 80)",
			score: 10, ti: urlpkg.TIResult{Matched: true, RiskScore: 50},
			want: "legitimate",
		},
		{
			name:  "Layer-2 phishing verdict overrides clean ML score",
			score: 5, mlVerdict: "phishing",
			want: "phishing",
		},
		{
			name:  "Routed to enrichment → suspicious",
			score: 30, routed: true,
			want: "suspicious",
		},
		{
			name:  "ML score ≥ 70 → phishing",
			score: 75,
			want:  "phishing",
		},
		{
			name:  "ML score ≥ 40 → suspicious",
			score: 50,
			want:  "suspicious",
		},
		{
			name:  "Clean URL → legitimate",
			score: 10,
			want:  "legitimate",
		},
		{
			name:  "TI high risk beats L2 benign",
			score: 10, ti: urlpkg.TIResult{Matched: true, RiskScore: 95}, mlVerdict: "benign",
			want: "phishing",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyLabel(tc.score, tc.ti, tc.routed, tc.mlVerdict)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ─── Handler: input validation ────────────────────────────────────────────────

func TestScanHandler_MissingURL(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(&fakeModel{}, &fakeTI{}, nil)
	w := doScanRaw(t, engine, `{"url":""}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(&fakeModel{}, &fakeTI{}, nil)
	w := doScanRaw(t, engine, `not json`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ─── Handler: Layer-2 disabled (nil scorer) ───────────────────────────────────

func TestScanHandler_NilScorer(t *testing.T) {
	t.Parallel()
	// L1 score is ignored for user-submitted scans; with no TI match and no
	// Layer-2 scorer the label falls back to "legitimate".
	engine := newTestEngine(
		&fakeModel{score: 45, prob: 0.45},
		&fakeTI{},
		nil,
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/path")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "legitimate", data["label"])
	assert.Empty(t, data["ml_verdict"], "ml_verdict must be absent when scorer is nil")
}

// ─── Handler: TI match skips Layer 2 ─────────────────────────────────────────

func TestScanHandler_TIMatchSkipsL2(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{result: phishing.Result{Verdict: "phishing", DeployP: 0.9}}
	engine := newTestEngine(
		&fakeModel{score: 10, prob: 0.1},
		&fakeTI{result: urlpkg.TIResult{Matched: true, RiskScore: 95, ThreatType: "phishing"}},
		scorer,
	)
	w, data := doScan(t, engine, "https://knownbad.invalid/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "phishing", data["label"])
	assert.Equal(t, 0, scorer.callCount(), "Layer-2 must NOT be called on TI match")
	assert.Empty(t, data["ml_verdict"], "ml_verdict must be absent on TI match")
}

// ─── Handler: TI miss calls Layer 2 ──────────────────────────────────────────

func TestScanHandler_TIMissCallsL2(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{
		result: phishing.Result{
			Verdict:  "benign",
			DeployP:  0.12,
			CacheHit: true,
		},
	}
	engine := newTestEngine(
		&fakeModel{score: 15, prob: 0.15},
		&fakeTI{}, // no TI match
		scorer,
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, scorer.callCount(), "Layer-2 must be called on TI miss")
	assert.Equal(t, "benign", data["ml_verdict"])
	assert.InDelta(t, 0.12, data["ml_deploy_p"], 0.001)
	assert.Equal(t, true, data["ml_cache_hit"])
	assert.Equal(t, "legitimate", data["label"])
}

// ─── Handler: Layer-2 phishing verdict upgrades label ─────────────────────────

func TestScanHandler_L2PhishingBoosts(t *testing.T) {
	t.Parallel()
	// ML score is low (5 → "legitimate"), but fusion ML says phishing.
	scorer := &fakeScorer{
		result: phishing.Result{Verdict: "phishing", DeployP: 0.72},
	}
	engine := newTestEngine(
		&fakeModel{score: 5, prob: 0.05},
		&fakeTI{},
		scorer,
	)
	w, data := doScan(t, engine, "https://subtle-phish.xyz/login")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "phishing", data["label"], "fusion ML phishing verdict must upgrade label")
	assert.Equal(t, "phishing", data["ml_verdict"])
	assert.InDelta(t, 0.72, data["ml_deploy_p"], 0.001)
}

// ─── Handler: Layer-2 error fail-open ─────────────────────────────────────────

func TestScanHandler_L2ErrorFailOpen(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{err: errors.New("sidecar unreachable")}
	engine := newTestEngine(
		&fakeModel{score: 20, prob: 0.20},
		&fakeTI{},
		scorer,
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/page")
	// Handler must still return 200 — Layer-2 failure is non-fatal.
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, data["ml_verdict"], "ml_verdict absent when Layer-2 errored")
	assert.Equal(t, "legitimate", data["label"])
}

// ─── Handler: degraded flag ───────────────────────────────────────────────────

func TestScanHandler_DegradedFlag(t *testing.T) {
	t.Parallel()
	// Neutral score (50 / 0.5) is what the pool returns when a worker is unavailable.
	engine := newTestEngine(
		&fakeModel{score: 50, prob: 0.5},
		&fakeTI{},
		nil,
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, data["degraded"])
}

// ─── Handler: concurrent safety ───────────────────────────────────────────────

func TestScanHandler_ConcurrentSafe(t *testing.T) {
	// Not parallel at the top level — spawns goroutines itself.
	scorer := &fakeScorer{result: phishing.Result{Verdict: "benign", DeployP: 0.05}}
	engine := newTestEngine(
		&fakeModel{score: 10, prob: 0.10},
		&fakeTI{},
		scorer,
	)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			w, data := doScan(t, engine, "https://concurrent-test.xyz/")
			assert.Equal(t, http.StatusOK, w.Code)
			assert.NotEmpty(t, data["label"])
		}()
	}
	wg.Wait()
	assert.Equal(t, n, scorer.callCount(), "each request must call Layer-2 exactly once")
}

// ─── Handler: TI match with low risk does not label phishing ─────────────────

func TestScanHandler_TILowRiskNotPhishing(t *testing.T) {
	t.Parallel()
	// TI match but risk score < 80 — classifyLabel ignores low-confidence
	// TI matches, so Layer 2 is invited to weigh in. With L2 returning
	// benign, the label stays non-phishing.
	scorer := &fakeScorer{result: phishing.Result{Verdict: "benign", DeployP: 0.1}}
	engine := newTestEngine(
		&fakeModel{score: 10, prob: 0.10},
		&fakeTI{result: urlpkg.TIResult{Matched: true, RiskScore: 60, ThreatType: "spam"}},
		scorer,
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, scorer.callCount(), "scorer must be called when TI risk < 80")
	assert.NotEqual(t, "phishing", data["label"])
}

// Regression: low-confidence TI match + L2 phishing verdict must escalate to
// phishing. Before the gate fix, L2 was skipped on any TI match.
func TestScanHandler_TILowRiskL2EscalatesPhishing(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{result: phishing.Result{Verdict: "phishing", DeployP: 0.85}}
	engine := newTestEngine(
		&fakeModel{score: 10, prob: 0.10},
		&fakeTI{result: urlpkg.TIResult{Matched: true, RiskScore: 30, ThreatType: "informational"}},
		scorer,
	)
	w, data := doScan(t, engine, "https://looks-bad.xyz/login")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, scorer.callCount(), "L2 must run on low-confidence TI match")
	assert.Equal(t, "phishing", data["label"])
	assert.Equal(t, "phishing", data["ml_verdict"])
}

// ─── Handler: domain guard fast-path ─────────────────────────────────────────

func TestScanHandler_DomainGuardAllowlisted(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{result: phishing.Result{Verdict: "phishing", DeployP: 0.99}}
	engine := newTestEngine(
		&fakeModel{score: 100, prob: 0.99},
		&fakeTI{result: urlpkg.TIResult{Matched: true, RiskScore: 95}},
		scorer,
	)
	// github.com is in the known-good list — short-circuits before model/TI/L2.
	w, data := doScan(t, engine, "https://github.com/login")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "legitimate", data["label"])
	assert.Equal(t, "allowlisted", data["guard_hit"])
	assert.Equal(t, 0, scorer.callCount(), "scorer must NOT be called for allowlisted domain")
}

func TestScanHandler_DomainGuardTyposquat(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{}
	engine := newTestEngine(
		&fakeModel{score: 0, prob: 0.01},
		&fakeTI{},
		scorer,
	)
	// "paypa1.com" is 1 edit from paypal.com — guard flags as typosquat.
	w, data := doScan(t, engine, "https://paypa1.com/login")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "phishing", data["label"])
	assert.Equal(t, "typosquat:paypal.com", data["guard_hit"])
	assert.Equal(t, 0, scorer.callCount(), "scorer must NOT be called for typosquat domain")
}

func TestScanHandler_DomainGuardCDNSubdomain(t *testing.T) {
	t.Parallel()
	// Deep CDN subdomain: apex is cloudflare.com → allowlisted.
	engine := newTestEngine(
		&fakeModel{score: 97, prob: 0.97},
		&fakeTI{},
		nil,
	)
	w, data := doScan(t, engine, "https://cdn.edge.static.cloudflare.com/assets/main.js")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "legitimate", data["label"])
	assert.Equal(t, "allowlisted", data["guard_hit"])
}

// ─── Handler: brand-in-subdomain guard ───────────────────────────────────────

func TestScanHandler_BrandInSubdomain(t *testing.T) {
	t.Parallel()
	scorer := &fakeScorer{}
	engine := newTestEngine(
		&fakeModel{score: 0, prob: 0.0},
		&fakeTI{},
		scorer,
	)
	cases := []struct {
		url   string
		brand string
	}{
		{"http://paypal-security.verify-login.com/account/suspended", "paypal"},
		{"https://microsoft-login-secure.netlify.app/oauth2/authorize", "microsoft"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.url, func(t *testing.T) {
			w, data := doScan(t, engine, tc.url)
			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "phishing", data["label"])
			assert.Equal(t, "brand-in-subdomain:"+tc.brand, data["guard_hit"])
			assert.Equal(t, 0, scorer.callCount(), "scorer must NOT be called for brand-in-subdomain")
		})
	}
}

// ─── Handler: response shape completeness ────────────────────────────────────

func TestScanHandler_ResponseShape(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(
		&fakeModel{score: 30, prob: 0.30},
		&fakeTI{},
		&fakeScorer{result: phishing.Result{Verdict: "benign", DeployP: 0.08}},
	)
	w, data := doScan(t, engine, "https://phish-test-site.xyz/check")
	require.Equal(t, http.StatusOK, w.Code)

	// All mandatory top-level fields must be present.
	for _, key := range []string{"url", "score", "probability", "label", "ti_match", "ti_risk_score", "degraded"} {
		assert.Contains(t, data, key, "response must contain field %q", key)
	}
	// Layer-2 fields present because scorer ran.
	assert.Contains(t, data, "ml_verdict")
	assert.Contains(t, data, "ml_deploy_p")
}
