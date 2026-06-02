package phishing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// sidecarReturning stands up a stub /score endpoint that always returns the
// given deploy_p and verdict.
func sidecarReturning(t *testing.T, deployP float64, sidecarVerdict string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"results": []map[string]interface{}{
				{
					"url":           "https://example.com/",
					"effective_url": "https://example.com/",
					"url_p":         0.1,
					"op_p":          0.2,
					"deploy_p":      deployP,
					"verdict":       sidecarVerdict,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDetector_ReappliesThresholdOverSidecar(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		deployP     float64
		threshold   float64
		sidecarSays string
		want        string
	}{
		{"below threshold → benign even if sidecar says phishing", 0.30, 0.50, "phishing", "benign"},
		{"above threshold → phishing even if sidecar says benign", 0.80, 0.50, "benign", "phishing"},
		{"equal to threshold → phishing", 0.50, 0.50, "benign", "phishing"},
		{"stricter Go threshold flips a borderline benign", 0.20, 0.10, "benign", "phishing"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			url := sidecarReturning(t, tc.deployP, tc.sidecarSays)
			d, err := NewDetector(Config{SidecarURL: url, Threshold: tc.threshold})
			require.NoError(t, err)
			defer d.Close()

			got, err := d.Score(context.Background(), "https://example.com/")
			require.NoError(t, err)
			require.Equal(t, tc.want, got.Verdict)
			require.InDelta(t, tc.deployP, got.DeployP, 0.0001)
		})
	}
}

func TestDetector_ScoreDetailedNilEnrichmentOnSidecarPath(t *testing.T) {
	t.Parallel()
	// No GeoIPDir → no Go enricher → /score path → enrichment must be nil,
	// while the verdict still resolves normally.
	url := sidecarReturning(t, 0.80, "phishing")
	d, err := NewDetector(Config{SidecarURL: url})
	require.NoError(t, err)
	defer d.Close()

	res, enriched, err := d.ScoreDetailed(context.Background(), "https://example.com/")
	require.NoError(t, err)
	require.Nil(t, enriched, "sidecar /score path must not surface enrichment")
	require.Equal(t, "phishing", res.Verdict)
	require.InDelta(t, 0.80, res.DeployP, 0.0001)
}

func TestDetector_DefaultThresholdApplied(t *testing.T) {
	t.Parallel()
	// Threshold left as zero → defaults to DefaultThreshold (0.50).
	url := sidecarReturning(t, 0.49, "phishing")
	d, err := NewDetector(Config{SidecarURL: url})
	require.NoError(t, err)
	defer d.Close()

	got, err := d.Score(context.Background(), "https://example.com/")
	require.NoError(t, err)
	require.Equal(t, "benign", got.Verdict, "0.49 < DefaultThreshold (0.50) → benign")
}
