// Package vt is SVC-05's minimal VirusTotal v3 client: a single file-report
// lookup by sha256 returning the last_analysis_stats vote summary.
//
// Two hard rules from ARCH-SPEC §1 step 3c drive its behaviour:
//
//   - No API key configured ⇒ SKIP: Lookup returns Skipped=true and a nil
//     error. SVC-05 must NEVER error just because VT is unconfigured.
//   - HTTP 429 (rate-limited) ⇒ FAIL-OPEN: Lookup returns Skipped=true (no
//     votes) and a nil error so scoring proceeds on hash + heuristics alone.
//
// A 404 (hash unknown to VT) is likewise a non-error miss. Any other transport
// or decode failure is returned so the caller can decide (SVC-05 treats it as a
// soft miss and proceeds, but the error is surfaced for metrics/logging).
package vt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the VirusTotal v3 API root.
const DefaultBaseURL = "https://www.virustotal.com/api/v3"

// Result is the parsed outcome of a file-report lookup.
type Result struct {
	// Skipped is true when the lookup did not produce a usable verdict because
	// VT was unconfigured (no key), rate-limited (429), or the hash was unknown
	// to VT (404). The caller treats a skipped result as "no VT signal".
	Skipped bool

	MaliciousVotes  int
	SuspiciousVotes int
	HarmlessVotes   int
	UndetectedVotes int

	// Raw is the verbatim JSON body VT returned, cached under
	// enrichment_results.raw_response. Empty on a skip with no body.
	Raw []byte
}

// Malicious reports whether VT's verdict flags the file (malicious_votes > 0).
func (r Result) Malicious() bool { return r.MaliciousVotes > 0 }

// Client is a configured VirusTotal file-report lookup client. The zero value
// is not usable; construct it with New.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// New builds a Client. An empty apiKey yields a client whose Lookup always
// returns a skipped result (so callers can wire it unconditionally and let the
// SKIP rule apply). timeout <= 0 falls back to 20s; baseURL "" falls back to
// DefaultBaseURL.
func New(apiKey, baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// Enabled reports whether an API key is configured. When false, Lookup always
// skips and SVC-05 never calls VT over the wire.
func (c *Client) Enabled() bool { return c != nil && c.apiKey != "" }

// Lookup fetches the VT file report for sha256. See the package doc for the
// SKIP (no key) and FAIL-OPEN (429) rules — both return (Skipped result, nil).
func (c *Client) Lookup(ctx context.Context, sha256 string) (Result, error) {
	if c == nil || c.apiKey == "" {
		// No key ⇒ SKIP, never error.
		return Result{Skipped: true}, nil
	}
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if sha256 == "" {
		return Result{Skipped: true}, nil
	}

	url := fmt.Sprintf("%s/files/%s", c.baseURL, sha256)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Skipped: true}, fmt.Errorf("vt: build request: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport failure: treat as a soft miss (fail-open) but surface the
		// error for metrics/logging.
		return Result{Skipped: true}, fmt.Errorf("vt: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to parse below
	case http.StatusTooManyRequests:
		// 429 ⇒ FAIL-OPEN: no votes, no error.
		return Result{Skipped: true}, nil
	case http.StatusNotFound:
		// Hash unknown to VT ⇒ a clean miss, no error.
		return Result{Skipped: true}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// A bad/expired key is a config problem, not a per-message failure;
		// skip so the pipeline keeps moving, but surface the error.
		return Result{Skipped: true}, fmt.Errorf("vt: auth rejected (status %d)", resp.StatusCode)
	default:
		return Result{Skipped: true}, fmt.Errorf("vt: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return Result{Skipped: true}, fmt.Errorf("vt: read body: %w", err)
	}

	stats, err := parseStats(body)
	if err != nil {
		return Result{Skipped: true, Raw: body}, fmt.Errorf("vt: decode: %w", err)
	}

	return Result{
		MaliciousVotes:  stats.Malicious,
		SuspiciousVotes: stats.Suspicious,
		HarmlessVotes:   stats.Harmless,
		UndetectedVotes: stats.Undetected,
		Raw:             body,
	}, nil
}

// analysisStats mirrors data.attributes.last_analysis_stats in the VT v3 file
// report.
type analysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

// parseStats extracts last_analysis_stats from a VT v3 file-report body. It is
// exported-via-Lookup only; kept package-private but split out for testability.
func parseStats(body []byte) (analysisStats, error) {
	var envelope struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats analysisStats `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if len(body) == 0 {
		return analysisStats{}, errors.New("empty body")
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return analysisStats{}, fmt.Errorf("unmarshal vt response: %w", err)
	}
	return envelope.Data.Attributes.LastAnalysisStats, nil
}
