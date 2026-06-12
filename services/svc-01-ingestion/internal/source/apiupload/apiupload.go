// Package apiupload is svc-01's API-upload EmailSource: POST /api/v1/scan
// accepts a raw RFC-822 .eml (Content-Type: message/rfc822 or text/plain) or a
// JSON body {"raw_rfc822": "<base64>", "message_id": "..."}. It normalises the
// request and hands it to the ingestion core. Auth (org binding) is enforced by
// the auth middleware that wraps the route — the adapter reads org_id/api_key_id
// from the request context, never from the body (G10).
package apiupload

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strings"

	"github.com/rs/zerolog"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source"
)

// adapterName labels emails.raw rows ingested over the API.
const adapterName = "api"

// maxBodyBytes caps an uploaded message at 25 MiB (comfortably above any sane
// email + attachments) so a runaway upload cannot exhaust memory.
const maxBodyBytes = 25 << 20

// Adapter is the API-upload EmailSource. It owns the /api/v1/scan handler and
// calls the ingestion core for each accepted upload.
type Adapter struct {
	core source.Ingestor
	log  zerolog.Logger
}

// New builds the API-upload adapter over the ingestion core.
func New(core source.Ingestor, log zerolog.Logger) *Adapter {
	return &Adapter{core: core, log: log}
}

// Name is the adapter's registry key.
func (a *Adapter) Name() string { return adapterName }

// Register binds the adapter's routes on the service mux.
func (a *Adapter) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/scan", a.handleScan)
}

// scanJSON is the JSON request shape. There is intentionally NO org_id field —
// the tenant is bound from the API key (G10), so a body org_id would be
// ignored; omitting it removes the spoofing surface entirely.
type scanJSON struct {
	RawRFC822 string `json:"raw_rfc822"`
	MessageID string `json:"message_id,omitempty"`
}

func (a *Adapter) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// The middleware already authenticated; the principal carries the only
	// trusted org_id + api_key_id. Its absence means the route was misconfigured
	// (not wrapped) — fail closed rather than ingest unauthenticated.
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	req, err := a.parseRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	outcome, err := a.core.Ingest(r.Context(), principal.OrgID, principal.APIKeyID, req)
	if err != nil {
		a.log.Error().Err(err).Int64("org_id", principal.OrgID).Msg("ingest failed")
		http.Error(w, "ingest failed", http.StatusInternalServerError)
		return
	}
	a.writeOutcome(w, outcome)
}

// parseRequest normalises either a raw .eml body or a JSON {raw_rfc822} body
// into a source.IngestRequest, deriving the dedup message_id from the RFC-822
// headers when the caller did not supply one.
func (a *Adapter) parseRequest(r *http.Request) (source.IngestRequest, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return source.IngestRequest{}, errors.New("read body failed")
	}
	if len(body) == 0 {
		return source.IngestRequest{}, errors.New("empty body")
	}

	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))

	var raw []byte
	var messageID string
	if contentType == "application/json" {
		var j scanJSON
		if err := json.Unmarshal(body, &j); err != nil {
			return source.IngestRequest{}, errors.New("invalid JSON body")
		}
		if j.RawRFC822 == "" {
			return source.IngestRequest{}, errors.New("raw_rfc822 is required")
		}
		decoded, derr := base64.StdEncoding.DecodeString(j.RawRFC822)
		if derr != nil {
			return source.IngestRequest{}, errors.New("raw_rfc822 must be valid base64")
		}
		raw = decoded
		messageID = j.MessageID
	} else {
		// Raw .eml upload (message/rfc822, text/plain, or unset). The bytes are
		// the message verbatim.
		raw = body
	}

	if len(raw) == 0 {
		return source.IngestRequest{}, errors.New("empty RFC-822 message")
	}
	if messageID == "" {
		messageID = messageIDFromRaw(raw)
	}

	return source.IngestRequest{
		Raw:           raw,
		MessageID:     messageID,
		SourceAdapter: adapterName,
	}, nil
}

// messageIDFromRaw extracts the RFC 5322 Message-ID from the raw message,
// stripping angle brackets so the dedup key matches svc-02's email_identities
// registration (which trims "<>"). Returns "" when the header is absent or the
// message is unparseable (such messages are simply not deduplicated).
func messageIDFromRaw(raw []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return ""
	}
	return strings.Trim(msg.Header.Get("Message-Id"), "<>")
}

// writeOutcome renders the ingestion outcome onto the HTTP response.
func (a *Adapter) writeOutcome(w http.ResponseWriter, o source.Outcome) {
	w.Header().Set("Content-Type", "application/json")
	switch o.Status {
	case source.StatusAccepted:
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "email_id": o.EmailID})
	case source.StatusDuplicate:
		// 200 + conflict marker: the email was already seen; nothing republished.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "duplicate"})
	case source.StatusQuotaExceeded:
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "quota_exceeded"})
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "error"})
	}
}

// compile-time assertion: the adapter satisfies EmailSource.
var _ source.EmailSource = (*Adapter)(nil)
