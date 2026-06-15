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
		name       string
		score      int
		ti         urlpkg.TIResult
		routed     bool
		mlVerdict  string
		mlDegraded bool
		want       string
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
			// The benign-URL fix: a high L1 score the L2 enricher clears must
			// de-escalate to legitimate rather than stay pinned at phishing.
			name:  "L2 benign overrides over-flagged L1 (>=70) → legitimate",
			score: 100, mlVerdict: "benign",
			want: "legitimate",
		},
		{
			name:  "L2 benign de-escalates ML-based suspicious → legitimate",
			score: 50, mlVerdict: "benign",
			want: "legitimate",
		},
		{
			// A degraded (breaker-open) benign verdict carries no signal, so a
			// high L1 score must stand — phishing recall is not regressed by a
			// network outage flipping every flagged URL to benign.
			name:  "degraded L2 benign does NOT override high L1 → phishing",
			score: 100, mlVerdict: "benign", mlDegraded: true,
			want: "phishing",
		},
		{
			// TI high-risk still wins outright over an L2 benign verdict.
			name:  "TI high risk beats L2 benign → phishing",
			score: 100, ti: urlpkg.TIResult{Matched: true, RiskScore: 90}, mlVerdict: "benign",
			want: "phishing",
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
			got := classifyLabel(tc.score, tc.ti, tc.routed, tc.mlVerdict, tc.mlDegraded)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEnvelopeScore(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		label      string
		inScore    int
		inProb     float64
		mlVerdict  string
		mlDegraded bool
		mlDeployP  float64
		wantScore  int
		wantProb   float64
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
			name:  "suspicious without L2 keeps the L1 score",
			label: "suspicious", inScore: 55, inProb: 0.55,
			wantScore: 55, wantProb: 0.55,
		},
		{
			name:  "legitimate without L2 keeps the L1 score",
			label: "legitimate", inScore: 10, inProb: 0.1,
			wantScore: 10, wantProb: 0.1,
		},
		{
			// The benign-URL fix: an L1 over-flag (98) the L2 enricher cleared to
			// benign (deploy_p 0.27) must publish the L2-derived score, not 98 —
			// otherwise the leftover L1 number re-flags the email.
			name:  "L2 benign pulls an over-flagged L1 score down to deploy_p",
			label: "legitimate", inScore: 98, inProb: 0.98,
			mlVerdict: "benign", mlDeployP: 0.27,
			wantScore: 27, wantProb: 0.27,
		},
		{
			// A degraded (breaker-open) benign verdict carries no signal, so it
			// must NOT pull the score down. (Label would already be phishing here,
			// pinning 100; this guards the L2 branch independently.)
			name:  "degraded L2 benign does not pull the score down",
			label: "legitimate", inScore: 98, inProb: 0.98,
			mlVerdict: "benign", mlDegraded: true, mlDeployP: 0,
			wantScore: 98, wantProb: 0.98,
		},
		{
			// Never inflate: a genuinely-benign URL whose L1 score is already
			// below the L2 estimate keeps its lower L1 score.
			name:  "L2 benign never raises an already-low L1 score",
			label: "legitimate", inScore: 5, inProb: 0.05,
			mlVerdict: "benign", mlDeployP: 0.30,
			wantScore: 5, wantProb: 0.05,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotScore, gotProb := envelopeScore(
				tc.label, tc.inScore, tc.inProb,
				tc.mlVerdict, tc.mlDegraded, tc.mlDeployP,
			)
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
		// High L1 no longer skips L2: a "looks-phishing" L1 must be verified by L2
		// (the benign over-flag fix). Only the confident-benign side early-exits.
		{"clearly phishing → run L2 (no skip)", l1ConfidentPhishingScore, false, urlpkg.TIResult{}, false},
		{"max phishing score → run L2 (no skip)", 100, false, urlpkg.TIResult{}, false},
		{"clearly benign → confident, skip L2", l1ConfidentBenignScore, false, urlpkg.TIResult{}, true},
		{"just below phishing cut → run L2", l1ConfidentPhishingScore - 1, false, urlpkg.TIResult{}, false},
		{"just above benign cut → uncertain", l1ConfidentBenignScore + 1, false, urlpkg.TIResult{}, false},
		{"mid-band → uncertain, run L2", 50, false, urlpkg.TIResult{}, false},
		{"routed always uncertain even if benign-scored", l1ConfidentBenignScore, true, urlpkg.TIResult{}, false},
		{"any TI match keeps it uncertain", l1ConfidentBenignScore, false, urlpkg.TIResult{Matched: true, RiskScore: 50}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, l1Confident(tc.score, tc.routed, tc.ti))
		})
	}
}

func TestIsUncorroboratedHighL1(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		label      string
		ti         urlpkg.TIResult
		mlVerdict  string
		mlOpP      float64
		mlDegraded bool
		want       bool
	}{
		{"non-phishing label is never de-escalated", "suspicious", urlpkg.TIResult{}, "", 0, false, false},
		{"benign label is never de-escalated", "legitimate", urlpkg.TIResult{}, "", 0, false, false},
		{
			// No L2 verdict (errored / timed out / no sidecar): there is nothing
			// to correct L1 with, so the L1 phishing call must STAND — recall is
			// not silently dropped when L2 is unavailable.
			"phishing from L1 only (no L2 verdict) stands — not de-escalated",
			"phishing", urlpkg.TIResult{}, "", 0, false, false,
		},
		{
			"phishing with operationally-backed L2 is corroborated",
			"phishing", urlpkg.TIResult{}, "phishing", 0.10, false, false,
		},
		{
			// The benign-FP case: L2 says phishing but purely on URL-structure
			// (op_p ~ 0), so it is a structural echo of L1, not corroboration.
			"phishing with L2 op_p below floor is uncorroborated",
			"phishing", urlpkg.TIResult{}, "phishing", 0.0006, false, true,
		},
		{
			"phishing with L2 op_p exactly at floor is corroborated",
			"phishing", urlpkg.TIResult{}, "phishing", l2OpSignalFloor, false, false,
		},
		{"phishing raised by TI>=80 is corroborated", "phishing", urlpkg.TIResult{Matched: true, RiskScore: 90}, "", 0, false, false},
		{
			// Low-confidence TI gives no corroboration, but there is also no L2
			// verdict to de-escalate with, so the L1 call stands.
			"phishing with low-conf TI<80 and no L2 stands",
			"phishing", urlpkg.TIResult{Matched: true, RiskScore: 50}, "", 0, false, false,
		},
		{
			// L2 benign would normally make classifyLabel return legitimate; if it
			// ever reaches here it is not a phishing echo, so do not de-escalate.
			"phishing with L2 benign verdict stands",
			"phishing", urlpkg.TIResult{}, "benign", 0, false, false,
		},
		{
			// Breaker-open: L2 returns a degraded fail-open benign with no signal.
			// classifyLabel keeps the high L1 as phishing; de-escalation must NOT
			// fire — recall is preserved during a network outage.
			"degraded L2 (breaker open) does not de-escalate high L1",
			"phishing", urlpkg.TIResult{}, "benign", 0, true, false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isUncorroboratedHighL1(tc.label, tc.ti, tc.mlVerdict, tc.mlOpP, tc.mlDegraded))
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
