package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ScoreRequest is a URL to score via the v2 sidecar.
type ScoreRequest struct {
	URL string
}

// ScoreResult holds the sidecar's scoring output for one URL.
type ScoreResult struct {
	URL          string
	EffectiveURL string
	URLP         float64
	OpP          float64
	DeployP      float64
	Verdict      string // "phishing" | "benign"
}

// Client calls the Python sidecar /score endpoint.
type Client struct {
	baseURL    string
	httpClient *http.Client
	cache      *Cache
}

// NewClient creates a Client pointing at baseURL.
func NewClient(baseURL string) (*Client, error) {
	cache, err := NewCache(0, 0)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
		cache: cache,
	}, nil
}

// Score enriches one URL and returns a score result.
func (c *Client) Score(ctx context.Context, req ScoreRequest) (ScoreResult, error) {
	results, err := c.ScoreBatch(ctx, []ScoreRequest{req})
	if err != nil {
		return ScoreResult{}, err
	}
	if len(results) == 0 {
		return ScoreResult{}, fmt.Errorf("sidecar returned empty results")
	}
	return results[0], nil
}

// ScoreBatch sends all URLs in one HTTP call to the v2 sidecar /score endpoint.
// The sidecar performs its own enrichment; no pre-computed features are needed.
func (c *Client) ScoreBatch(ctx context.Context, reqs []ScoreRequest) ([]ScoreResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	type wirePayload struct {
		URLs []string `json:"urls"`
	}
	type wireResult struct {
		URL          string  `json:"url"`
		EffectiveURL string  `json:"effective_url"`
		URLP         float64 `json:"url_p"`
		OpP          float64 `json:"op_p"`
		DeployP      float64 `json:"deploy_p"`
		Verdict      string  `json:"verdict"`
	}
	type wireResponse struct {
		Results []wireResult `json:"results"`
	}

	urls := make([]string, len(reqs))
	for i, r := range reqs {
		urls[i] = r.URL
	}

	body, err := json.Marshal(wirePayload{URLs: urls})
	if err != nil {
		return nil, fmt.Errorf("marshal score request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar returned status %d", resp.StatusCode)
	}

	var wireResp wireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wireResp); err != nil {
		return nil, fmt.Errorf("decode sidecar response: %w", err)
	}

	results := make([]ScoreResult, len(wireResp.Results))
	for i, r := range wireResp.Results {
		results[i] = ScoreResult{
			URL:          r.URL,
			EffectiveURL: r.EffectiveURL,
			URLP:         r.URLP,
			OpP:          r.OpP,
			DeployP:      r.DeployP,
			Verdict:      r.Verdict,
		}
	}
	return results, nil
}

// CachedScore returns from the LRU cache if available, otherwise calls Score.
// The cache key is the apex domain of the URL.
func (c *Client) CachedScore(ctx context.Context, url, apexKey string) (ScoreResult, bool, error) {
	if hit, ok := c.cache.Get(apexKey); ok {
		return hit, true, nil
	}
	result, err := c.Score(ctx, ScoreRequest{URL: url})
	if err != nil {
		return ScoreResult{}, false, err
	}
	c.cache.Set(apexKey, result)
	return result, false, nil
}
