// svc-01-ingestion accepts an ingest request over HTTP (JSON or multipart) and
// emits emails.raw. It authenticates the caller with an API key (shared/auth),
// derives org_id from that key, rate-limits and de-duplicates per org, and
// publishes. It no longer INSERTs the `emails` row — SVC-02 is the authoritative
// writer (a pre-insert here would collide and make SVC-02 skip its writes).
//
// email_id / org_id are int64 BIGINT for now (UUIDv7 migration tracked
// separately). NO Gmail/Outlook/IMAP adapters yet.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/shared/auth"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/svckit"
)

const (
	serviceName = "svc-01-ingestion"
	// reqPerMin is the per-org ingest rate limit.
	reqPerMin = 100
	// dedupTTLSeconds is how long a (org, message_id) is remembered for dedup.
	dedupTTLSeconds = 7 * 24 * 60 * 60
	// maxUploadBytes caps a multipart email upload.
	maxUploadBytes = 32 << 20
)

type ingestRequest struct {
	EmailID       int64             `json:"email_id,omitempty"`
	OrgID         int64             `json:"org_id,omitempty"`
	MessageID     string            `json:"message_id,omitempty"`
	SourceAdapter string            `json:"source_adapter,omitempty"`
	RawMessageB64 string            `json:"raw_message_b64,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ProducerTopics: []string{contracts.TopicEmailsRaw},
		HTTPPort:       8081,
		HTTPRoutes: func(mux *http.ServeMux, deps svckit.Deps) {
			authn := auth.New(dbsqlc.New(deps.Pool), deps.Cfg.Auth)
			h := ingestHandler(deps.Valkey, deps.Pool, deps.Producers[contracts.TopicEmailsRaw], deps.Log)
			// API-key auth runs first; the handler reads org_id from context.
			mux.Handle("/ingest", authn.RequireAPIKey(h))
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func ingestHandler(vk valkeygo.Client, pool *pgxpool.Pool, prod *kafkaproducer.Producer, log zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		// org_id comes from the authenticated API key (auth middleware).
		orgID := auth.OrgIDFromContext(r.Context())
		if orgID == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if allowed, err := allowRequest(ctx, vk, orgID); err != nil {
			log.Warn().Err(err).Int64("org_id", orgID).Msg("rate-limit check failed; allowing")
		} else if !allowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
			return
		}

		req, err := parseIngest(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		req.OrgID = orgID // authoritative; ignore any client-supplied org_id
		now := time.Now().UTC()
		if req.EmailID == 0 {
			req.EmailID = now.UnixNano() / 1000
		}
		if req.SourceAdapter == "" {
			req.SourceAdapter = "http"
		}

		// Dedup: a repeated (org, message_id) within the window is acknowledged
		// but not re-published downstream.
		if req.MessageID != "" {
			dup, err := isDuplicate(ctx, vk, pool, orgID, req.MessageID, req.EmailID, now)
			if err != nil {
				log.Warn().Err(err).Msg("dedup check failed; treating as new")
			} else if dup {
				writeJSON(w, http.StatusOK, map[string]any{"status": "duplicate", "email_id": req.EmailID})
				return
			}
		}

		payload := contracts.EmailsRaw{
			Meta:          contracts.NewMeta(req.EmailID, req.OrgID),
			FetchedAt:     now,
			SourceAdapter: req.SourceAdapter,
			MessageID:     req.MessageID,
			RawMessageB64: req.RawMessageB64,
			Headers:       req.Headers,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "marshal failed"})
			return
		}
		key := []byte(strconv.FormatInt(req.EmailID, 10))
		if err := prod.Publish(ctx, key, body, 3); err != nil {
			log.Error().Err(err).Int64("email_id", req.EmailID).Msg("publish emails.raw failed")
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "publish failed"})
			return
		}

		log.Info().Int64("email_id", req.EmailID).Int64("org_id", orgID).Msg("ingested email")
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "email_id": req.EmailID})
	})
}

// parseIngest reads an ingest request from either a JSON body or a
// multipart/form-data upload (file field "email"; optional message_id /
// source_adapter form fields).
func parseIngest(r *http.Request) (ingestRequest, error) {
	ct := r.Header.Get("Content-Type")
	if len(ct) >= 19 && ct[:19] == "multipart/form-data" {
		if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
			return ingestRequest{}, fmt.Errorf("parse multipart: %w", err)
		}
		file, _, err := r.FormFile("email")
		if err != nil {
			return ingestRequest{}, errors.New("multipart: missing 'email' file field")
		}
		defer func() { _ = file.Close() }()
		raw, err := io.ReadAll(io.LimitReader(file, maxUploadBytes))
		if err != nil {
			return ingestRequest{}, fmt.Errorf("read upload: %w", err)
		}
		return ingestRequest{
			MessageID:     r.FormValue("message_id"),
			SourceAdapter: r.FormValue("source_adapter"),
			RawMessageB64: base64.StdEncoding.EncodeToString(raw),
		}, nil
	}

	var req ingestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxUploadBytes)).Decode(&req); err != nil {
		return ingestRequest{}, errors.New("bad json")
	}
	return req, nil
}

// allowRequest enforces a fixed-window per-org rate limit in Valkey. It fails
// open (returns true) on a cache error so a Redis blip doesn't drop ingestion.
func allowRequest(ctx context.Context, vk valkeygo.Client, orgID int64) (bool, error) {
	if vk == nil {
		return true, nil
	}
	key := fmt.Sprintf("ratelimit:{%d}:%d", orgID, time.Now().Unix()/60)
	count, err := vk.Do(ctx, vk.B().Incr().Key(key).Build()).ToInt64()
	if err != nil {
		return true, fmt.Errorf("ratelimit incr: %w", err)
	}
	if count == 1 {
		_ = vk.Do(ctx, vk.B().Expire().Key(key).Seconds(60).Build()).Error()
	}
	return count <= reqPerMin, nil
}

// isDuplicate reports whether (orgID, messageID) was already ingested. It uses a
// Valkey SET NX fast path and falls back to the email_identities table when
// Valkey is unavailable.
func isDuplicate(
	ctx context.Context, vk valkeygo.Client, pool *pgxpool.Pool,
	orgID int64, messageID string, emailID int64, fetchedAt time.Time,
) (bool, error) {
	if vk != nil {
		key := fmt.Sprintf("dedup:{%d}:%s", orgID, messageID)
		err := vk.Do(ctx, vk.B().Set().Key(key).Value("1").Nx().ExSeconds(dedupTTLSeconds).Build()).Error()
		if err == nil {
			return false, nil // key set ⇒ first time seen
		}
		if valkeygo.IsValkeyNil(err) {
			return true, nil // NX failed ⇒ already present
		}
		// Valkey error → fall through to the DB.
	}
	return registerIdentity(ctx, pool, orgID, messageID, emailID, fetchedAt)
}

// registerIdentity records the (org, message_id) identity in email_identities
// and reports whether it already existed (duplicate). It is the durable dedup
// of record (migration 015).
func registerIdentity(
	ctx context.Context, pool *pgxpool.Pool,
	orgID int64, messageID string, emailID int64, fetchedAt time.Time,
) (bool, error) {
	if pool == nil {
		return false, errors.New("svc-01: no DB pool for dedup fallback")
	}
	const q = `
INSERT INTO email_identities (org_id, message_id, internal_id, fetched_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, message_id) DO NOTHING`
	tag, err := pool.Exec(ctx, q, orgID, messageID, emailID, fetchedAt)
	if err != nil {
		return false, fmt.Errorf("svc-01: register email identity: %w", err)
	}
	return tag.RowsAffected() == 0, nil // 0 rows ⇒ conflict ⇒ duplicate
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
