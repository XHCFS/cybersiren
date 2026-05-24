package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var clientTracer = otel.Tracer("svc-03-url-analysis/phishing-client")

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
	metrics    *Metrics
}

// NewClient creates a Client pointing at baseURL with no metrics reporting.
func NewClient(baseURL string) (*Client, error) {
	return NewClientWithMetrics(baseURL, nil)
}

// NewClientWithMetrics is like NewClient but bumps Prometheus counters on
// cache hits/misses, sidecar errors, and score durations.
func NewClientWithMetrics(baseURL string, m *Metrics) (*Client, error) {
	cache, err := NewCache(0, 0)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
		cache:   cache,
		metrics: m,
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

	ctx, span := clientTracer.Start(ctx, "phishing.client.ScoreBatch",
		trace.WithAttributes(attribute.Int("phishing.batch_size", len(reqs))),
	)
	defer span.End()

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
		c.metrics.incSidecarError("encode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("marshal score request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score", bytes.NewReader(body))
	if err != nil {
		c.metrics.incSidecarError("encode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.metrics.incSidecarError("http")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("sidecar request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.metrics.incSidecarError("status")
		statusErr := fmt.Errorf("sidecar returned status %d", resp.StatusCode)
		span.SetStatus(codes.Error, statusErr.Error())
		return nil, statusErr
	}

	var wireResp wireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wireResp); err != nil {
		c.metrics.incSidecarError("decode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("decode sidecar response: %w", err)
	}

	// Only observe latency on success — error paths above already counted
	// distinct failure modes and would skew the duration histogram.
	c.metrics.observeDuration(time.Since(start).Seconds())

	results := make([]ScoreResult, len(wireResp.Results))
	for i, r := range wireResp.Results {
		results[i] = ScoreResult(r)
	}
	return results, nil
}

// CachedScore returns from the LRU cache if available, otherwise calls Score.
//
// The cache key is the full URL — not the apex domain — because the sidecar's
// url_p is computed on the URL string and is path-dependent (e.g.
// github.com/login differs from github.com/foo). When url is empty the cache
// is bypassed entirely. apexKey is accepted for backwards compatibility and
// is unused.
func (c *Client) CachedScore(ctx context.Context, url, apexKey string) (ScoreResult, bool, error) {
	_ = apexKey
	if url == "" {
		result, err := c.Score(ctx, ScoreRequest{URL: url})
		if err != nil {
			return ScoreResult{}, false, err
		}
		return result, false, nil
	}
	if hit, ok := c.cache.Get(url); ok {
		c.metrics.setCacheItems(c.cache.Len())
		return hit, true, nil
	}
	result, err := c.Score(ctx, ScoreRequest{URL: url})
	if err != nil {
		return ScoreResult{}, false, err
	}
	c.cache.Set(url, result)
	c.metrics.setCacheItems(c.cache.Len())
	return result, false, nil
}

// FeatureRequest is one element of the /score-features POST body. The Go
// enricher constructs these so the sidecar can score without re-enriching.
type FeatureRequest struct {
	// NormalizedURL is the URL after shortener resolution (the same string
	// the sidecar would have produced via its own enrichment).
	NormalizedURL string
	// IsShortener is true when the original URL was a known shortener apex.
	IsShortener bool
	// Features is the flat dict of operational features (the 44 columns
	// produced by enricher.FeatureVector.ToJSON()).
	Features map[string]interface{}
}

// ScoreFeaturesBatch POSTs precomputed features to /score-features. The
// sidecar skips its own enrichment entirely — it only runs url_p + op_p +
// fusion over the supplied feature dict. Bumps the same metrics as
// ScoreBatch.
func (c *Client) ScoreFeaturesBatch(ctx context.Context, reqs []FeatureRequest) ([]ScoreResult, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	ctx, span := clientTracer.Start(ctx, "phishing.client.ScoreFeaturesBatch",
		trace.WithAttributes(attribute.Int("phishing.batch_size", len(reqs))),
	)
	defer span.End()

	type wireFeatureReq struct {
		NormalizedURL string                 `json:"normalized_url"`
		IsShortener   bool                   `json:"is_shortener"`
		Features      map[string]interface{} `json:"features"`
	}
	type wirePayload struct {
		Requests []wireFeatureReq `json:"requests"`
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

	wireReqs := make([]wireFeatureReq, len(reqs))
	for i, r := range reqs {
		wireReqs[i] = wireFeatureReq(r)
	}
	body, err := json.Marshal(wirePayload{Requests: wireReqs})
	if err != nil {
		c.metrics.incSidecarError("encode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("marshal score-features request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score-features", bytes.NewReader(body))
	if err != nil {
		c.metrics.incSidecarError("encode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.metrics.incSidecarError("http")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("sidecar request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.metrics.incSidecarError("status")
		statusErr := fmt.Errorf("sidecar returned status %d", resp.StatusCode)
		span.SetStatus(codes.Error, statusErr.Error())
		return nil, statusErr
	}

	var wireResp wireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wireResp); err != nil {
		c.metrics.incSidecarError("decode")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("decode sidecar response: %w", err)
	}

	c.metrics.observeDuration(time.Since(start).Seconds())

	results := make([]ScoreResult, len(wireResp.Results))
	for i, r := range wireResp.Results {
		results[i] = ScoreResult(r)
	}
	return results, nil
}

// CachedScoreFeatures is the /score-features analog of CachedScore. The
// cache key is the request's NormalizedURL (since two identical
// normalized URLs always produce the same enriched feature vector after
// the cache TTL expires).
func (c *Client) CachedScoreFeatures(ctx context.Context, req FeatureRequest) (ScoreResult, bool, error) {
	key := req.NormalizedURL
	if key == "" {
		// No URL key → bypass cache.
		results, err := c.ScoreFeaturesBatch(ctx, []FeatureRequest{req})
		if err != nil {
			return ScoreResult{}, false, err
		}
		if len(results) == 0 {
			return ScoreResult{}, false, fmt.Errorf("sidecar returned empty results")
		}
		return results[0], false, nil
	}
	if hit, ok := c.cache.Get(key); ok {
		c.metrics.setCacheItems(c.cache.Len())
		return hit, true, nil
	}
	results, err := c.ScoreFeaturesBatch(ctx, []FeatureRequest{req})
	if err != nil {
		return ScoreResult{}, false, err
	}
	if len(results) == 0 {
		return ScoreResult{}, false, fmt.Errorf("sidecar returned empty results")
	}
	c.cache.Set(key, results[0])
	c.metrics.setCacheItems(c.cache.Len())
	return results[0], false, nil
}
