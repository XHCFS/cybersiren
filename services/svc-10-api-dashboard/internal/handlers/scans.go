package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// maxScanUpload caps an uploaded message at 25 MiB, matching svc-01's body cap.
const maxScanUpload = 25 << 20

// ScanResult is svc-01's scan outcome echoed back to the SPA.
type ScanResult struct {
	Status  string `json:"status"`
	EmailID string `json:"email_id,omitempty"`
}

// errUpstreamUnauthorized signals the svc-01 API key was rejected (a server
// misconfiguration, surfaced as 502 to the browser — the SPA never sees the key).
var errUpstreamUnauthorized = errors.New("svc-01 rejected the forwarding credential")

// ScanForwarder proxies scan submissions to svc-01 using a SERVER-SIDE API key.
// The key is never exposed to the browser.
type ScanForwarder struct {
	scanURL string
	apiKey  string
	client  *http.Client
	log     zerolog.Logger
}

// NewScanForwarder builds the proxy. scanURL is the full svc-01 scan endpoint.
func NewScanForwarder(scanURL, apiKey string, log zerolog.Logger) *ScanForwarder {
	return &ScanForwarder{
		scanURL: scanURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 30 * time.Second},
		log:     log,
	}
}

// scanJSON is the optional JSON request shape (base64 RFC-822).
type scanJSON struct {
	RawRFC822 string `json:"raw_rfc822"`
}

// HandleScan accepts a raw message/rfc822 upload (or JSON {raw_rfc822: base64})
// and forwards it to svc-01 with the server-side API key, returning svc-01's
// {status, email_id}. Upstream-down → 502; upstream-401 → 502 (the credential is
// the server's, not the caller's).
func (a *API) HandleScan(w http.ResponseWriter, r *http.Request) {
	if a.Scan == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("scan forwarding not configured"))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	raw, err := readScanBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	res, err := a.Scan.Forward(r.Context(), raw)
	if errors.Is(err, errUpstreamUnauthorized) {
		a.Log.Error().Err(err).Msg("svc-01 rejected svc-10 forwarding key")
		writeJSON(w, http.StatusBadGateway, errBody("upstream rejected the request"))
		return
	}
	if err != nil {
		a.Log.Error().Err(err).Msg("forward to svc-01 failed")
		writeJSON(w, http.StatusBadGateway, errBody("could not reach the scan service"))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// readScanBody extracts the raw RFC-822 bytes from either a JSON or raw body.
func readScanBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxScanUpload))
	if err != nil {
		return nil, errors.New("could not read request body")
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if contentType == "application/json" {
		var j scanJSON
		if err := json.Unmarshal(body, &j); err != nil {
			return nil, errors.New("invalid JSON body")
		}
		if j.RawRFC822 == "" {
			return nil, errors.New("raw_rfc822 is required")
		}
		decoded, derr := base64.StdEncoding.DecodeString(j.RawRFC822)
		if derr != nil {
			return nil, errors.New("raw_rfc822 must be valid base64")
		}
		body = decoded
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("empty message body")
	}
	return body, nil
}

// Forward POSTs the raw message to svc-01 with the server-side Bearer key.
func (f *ScanForwarder) Forward(ctx context.Context, raw []byte) (ScanResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.scanURL, bytes.NewReader(raw))
	if err != nil {
		return ScanResult{}, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("Authorization", "Bearer "+f.apiKey)

	resp, err := f.client.Do(req)
	if err != nil {
		return ScanResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusUnauthorized {
		return ScanResult{}, errUpstreamUnauthorized
	}
	var out ScanResult
	_ = json.Unmarshal(respBody, &out)
	if out.Status == "" {
		out.Status = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return out, nil
}
