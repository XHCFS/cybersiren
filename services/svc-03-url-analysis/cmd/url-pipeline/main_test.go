package main

// Unit tests for the pipeline's classifyLabel function.
// These run without any external services.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

func TestPipelineClassifyLabel(t *testing.T) {
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
			score: 5, ti: urlpkg.TIResult{Matched: true, RiskScore: 90},
			want: "phishing",
		},
		{
			name:  "TI match risk < 80 → not phishing from TI",
			score: 5, ti: urlpkg.TIResult{Matched: true, RiskScore: 70},
			want: "legitimate",
		},
		{
			name:  "Layer-2 phishing verdict → phishing even with clean ML",
			score: 5, mlVerdict: "phishing",
			want: "phishing",
		},
		{
			name:  "Routed → suspicious",
			score: 20, routed: true,
			want: "suspicious",
		},
		{
			name:  "ML score ≥ 70 → phishing",
			score: 80,
			want:  "phishing",
		},
		{
			name:  "ML score ≥ 40 → suspicious",
			score: 55,
			want:  "suspicious",
		},
		{
			name:  "Clean → legitimate",
			score: 10,
			want:  "legitimate",
		},
		{
			name:  "Layer-2 benign does not change ML-based suspicious",
			score: 50, mlVerdict: "benign",
			want: "suspicious",
		},
		{
			name:  "Layer-2 phishing overrides routed-only suspicious",
			score: 30, routed: true, mlVerdict: "phishing",
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

func TestPhishingScore(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		label     string
		inScore   int
		inProb    float64
		wantScore int
		wantProb  float64
	}{
		{
			// The regression: a TI/L2-confirmed phish whose L1 XGBoost score is
			// low must still publish a confirmed-phishing envelope score so it is
			// not under-weighted in svc-07's numeric fusion.
			name:  "phishing with low L1 score is raised to 100",
			label: "phishing", inScore: 5, inProb: 0.05,
			wantScore: 100, wantProb: 1.0,
		},
		{
			name:  "phishing already high is pinned to 100",
			label: "phishing", inScore: 80, inProb: 0.8,
			wantScore: 100, wantProb: 1.0,
		},
		{
			name:  "suspicious keeps the L1 score",
			label: "suspicious", inScore: 55, inProb: 0.55,
			wantScore: 55, wantProb: 0.55,
		},
		{
			name:  "legitimate keeps the L1 score",
			label: "legitimate", inScore: 10, inProb: 0.1,
			wantScore: 10, wantProb: 0.1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotScore, gotProb := phishingScore(tc.label, tc.inScore, tc.inProb)
			assert.Equal(t, tc.wantScore, gotScore)
			assert.InDelta(t, tc.wantProb, gotProb, 1e-9)
		})
	}
}

func extractedURLs(urls ...string) []contracts.ExtractedURL {
	out := make([]contracts.ExtractedURL, len(urls))
	for i, u := range urls {
		out[i] = contracts.ExtractedURL{URL: u}
	}
	return out
}

func TestDedupAndCapURLs(t *testing.T) {
	t.Parallel()

	t.Run("dedups by normalized form, keeps first occurrence", func(t *testing.T) {
		t.Parallel()
		// These normalize to the same canonical form (trailing slash / case).
		in := extractedURLs(
			"https://example.com",
			"https://example.com/",
			"https://EXAMPLE.com",
			"https://other.com/path",
		)
		kept, deduped, truncated := dedupAndCapURLs(in)
		assert.Equal(t, []string{"https://example.com", "https://other.com/path"}, kept)
		assert.Equal(t, 2, deduped)
		assert.Equal(t, 0, truncated)
	})

	t.Run("caps at maxURLsPerEmail after dedup", func(t *testing.T) {
		t.Parallel()
		var urls []string
		for i := 0; i < maxURLsPerEmail+5; i++ {
			urls = append(urls, fmt.Sprintf("https://distinct-%d.example.com/", i))
		}
		kept, deduped, truncated := dedupAndCapURLs(extractedURLs(urls...))
		assert.Len(t, kept, maxURLsPerEmail)
		assert.Equal(t, 0, deduped)
		assert.Equal(t, 5, truncated)
		// Cap keeps the FIRST N in order.
		assert.Equal(t, "https://distinct-0.example.com/", kept[0])
	})

	t.Run("unnormalizable URLs are kept and deduped on raw form", func(t *testing.T) {
		t.Parallel()
		in := extractedURLs("not a url", "not a url", "also::bad")
		kept, deduped, _ := dedupAndCapURLs(in)
		// "not a url" appears twice → one drop; the distinct bad one survives.
		assert.Equal(t, 1, deduped)
		assert.Contains(t, kept, "not a url")
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		kept, deduped, truncated := dedupAndCapURLs(nil)
		assert.Empty(t, kept)
		assert.Zero(t, deduped)
		assert.Zero(t, truncated)
	})
}

func TestL1Confident(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		score  int
		routed bool
		ti     urlpkg.TIResult
		want   bool
	}{
		{"clearly phishing → confident, skip L2", l1ConfidentPhishingScore, false, urlpkg.TIResult{}, true},
		{"clearly benign → confident, skip L2", l1ConfidentBenignScore, false, urlpkg.TIResult{}, true},
		{"just below phishing cut → uncertain", l1ConfidentPhishingScore - 1, false, urlpkg.TIResult{}, false},
		{"just above benign cut → uncertain", l1ConfidentBenignScore + 1, false, urlpkg.TIResult{}, false},
		{"mid-band → uncertain, run L2", 50, false, urlpkg.TIResult{}, false},
		{"routed always uncertain even if benign-scored", l1ConfidentBenignScore, true, urlpkg.TIResult{}, false},
		{"any TI match keeps it uncertain", l1ConfidentPhishingScore, false, urlpkg.TIResult{Matched: true, RiskScore: 50}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, l1Confident(tc.score, tc.routed, tc.ti))
		})
	}
}

func TestWorseLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b, want string
	}{
		{"legitimate", "legitimate", "legitimate"},
		{"legitimate", "suspicious", "suspicious"},
		{"suspicious", "legitimate", "suspicious"},
		{"suspicious", "phishing", "phishing"},
		{"phishing", "suspicious", "phishing"},
		{"phishing", "phishing", "phishing"},
		{"legitimate", "phishing", "phishing"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, worseLabel(tc.a, tc.b))
		})
	}
}
