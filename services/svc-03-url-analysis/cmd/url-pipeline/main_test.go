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
			name:      "Layer-2 phishing verdict → phishing even with clean ML",
			score:     5, mlVerdict: "phishing",
			want: "phishing",
		},
		{
			name:   "Routed → suspicious",
			score:  20, routed: true,
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
			name:      "Layer-2 benign does not change ML-based suspicious",
			score:     50, mlVerdict: "benign",
			want: "suspicious",
		},
		{
			name:      "Layer-2 phishing overrides routed-only suspicious",
			score:     30, routed: true, mlVerdict: "phishing",
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
