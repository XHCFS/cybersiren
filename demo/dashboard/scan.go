package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"

	"github.com/rs/zerolog"
)

const maxUpload = 25 << 20 // 25 MiB — matches svc-01's body cap

type handlers struct {
	cfg    config
	st     *store
	gm     *gmailConnector
	log    zerolog.Logger
	client *http.Client
}

type scanResult struct {
	Status  string `json:"status"`
	EmailID string `json:"email_id,omitempty"`
}

// forwardToSvc01 posts a raw RFC-822 message to svc-01's API-upload endpoint
// with the server-side demo API key, returning svc-01's scan outcome. The demo
// key never reaches the browser.
func forwardToSvc01(ctx context.Context, client *http.Client, cfg config, raw []byte) (scanResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.SVC01ScanURL, bytes.NewReader(raw))
	if err != nil {
		return scanResult{}, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("Authorization", "Bearer "+cfg.DemoAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return scanResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusUnauthorized {
		return scanResult{}, fmt.Errorf("svc-01 rejected the demo API key (401)")
	}
	var out scanResult
	_ = json.Unmarshal(body, &out)
	if out.Status == "" {
		out.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	}
	return out, nil
}

// parseEmailMeta extracts a display subject + from address from raw RFC-822
// (best-effort — purely cosmetic for the feed).
func parseEmailMeta(raw []byte) (subject, from string) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", ""
	}
	subject = m.Header.Get("Subject")
	from = m.Header.Get("From")
	if addr, err := mail.ParseAddress(from); err == nil {
		if addr.Name != "" {
			from = addr.Name + " <" + addr.Address + ">"
		} else {
			from = addr.Address
		}
	}
	return subject, from
}

func (h *handlers) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxUpload))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty .eml body"})
		return
	}
	res, err := forwardToSvc01(r.Context(), h.client, h.cfg, raw)
	if err != nil {
		h.log.Error().Err(err).Msg("forward to svc-01 failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if res.EmailID != "" {
		subject, from := parseEmailMeta(raw)
		h.st.recordSubmit(res.EmailID, "upload", subject, from)
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handlers) handleVerdict(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("email_id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email_id required"})
		return
	}
	sc := h.st.get(id)
	if sc == nil {
		writeJSON(w, http.StatusOK, scanView{EmailID: id, Status: "pending", Modules: modulesView{}})
		return
	}
	writeJSON(w, http.StatusOK, viewOf(sc))
}

func (h *handlers) handleScans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"scans": h.st.feedItems()})
}

func (h *handlers) handleGmailStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.gm.status())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
