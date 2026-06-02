// svc-01-ingestion accepts an ingest request over HTTP and emits emails.raw.
// It no longer INSERTs the `emails` row — SVC-02 (the parser) is the
// authoritative writer of the row + its junction tables. The row SVC-01 used to
// write here would collide with SVC-02's insert (same (internal_id, fetched_at)
// key) and make SVC-02 skip all of its writes, so ingestion now only
// authenticates, mints the logical email_id, and publishes. NO Gmail/Outlook/
// IMAP adapters yet.
//
// email_id / org_id remain int64 BIGINT values for now (the UUIDv7 migration is
// tracked separately).
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-01-ingestion"

const stubOrgID int64 = 1

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
		ProducerTopics: []string{contracts.TopicEmailsRaw},
		HTTPPort:       8081,
		HTTPRoutes: func(mux *http.ServeMux, deps svckit.Deps) {
			mux.HandleFunc("/ingest", ingestHandler(deps.Producers[contracts.TopicEmailsRaw], deps.Log))
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func ingestHandler(prod *kafkaproducer.Producer, log zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		var req ingestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		now := time.Now().UTC()
		if req.EmailID == 0 {
			// time.Now().UnixNano()/1000 ⇒ collision-resistant int64 that fits
			// in BIGINT and stays roughly monotonic. UUIDv7 migration pending.
			req.EmailID = now.UnixNano() / 1000
		}
		if req.OrgID == 0 {
			req.OrgID = stubOrgID
		}
		if req.SourceAdapter == "" {
			req.SourceAdapter = "http-stub"
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

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
			http.Error(w, "marshal failed", http.StatusInternalServerError)
			return
		}

		key := []byte(strconv.FormatInt(req.EmailID, 10))
		// Publish last arg: extra kafka retries after first attempt.
		if err := prod.Publish(ctx, key, body, 3); err != nil {
			log.Error().Err(err).Int64("email_id", req.EmailID).Msg("publish emails.raw failed")
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}

		log.Info().Int64("email_id", req.EmailID).Msg("ingested email")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "email_id": req.EmailID})
	}
}
