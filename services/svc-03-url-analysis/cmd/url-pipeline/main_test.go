package main

// Unit tests for the pipeline's classifyLabel function.
// These run without any external services.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	urlpkg "github.com/saif/cybersiren/services/svc-03-url-analysis/internal/url"
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
