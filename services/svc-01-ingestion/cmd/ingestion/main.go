// STUB: replace with real implementation. Accepts a synthetic ingest request
// over HTTP and emits emails.raw. NO Gmail/Outlook/IMAP adapters.
//
// In v0 the email_id and org_id are int64 BIGINT values (matching
// emails.internal_id / orgs.id), generated from the request when not
// supplied — once the real ingestion path lands they will come from the
// INSERT into emails.
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

type ingestRequest struct {
	EmailID       int64             `json:"email_id,omitempty"`
	OrgID         int64             `json:"org_id,omitempty"`
	MessageID     string            `json:"message_id,omitempty"`
	SourceAdapter string            `json:"source_adapter,omitempty"`
	RawMessageB64 string            `json:"raw_message_b64,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

const stubOrgID int64 = 1

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
			// time.Now().UnixNano() / 1000 ⇒ collision-resistant int64 that
			// fits comfortably in BIGINT and stays roughly monotonic for
			// log-grep scanning. Real ingestion will use BIGSERIAL.
			req.EmailID = now.UnixNano() / 1000
		}
		if req.OrgID == 0 {
			req.OrgID = stubOrgID
		}
		if req.SourceAdapter == "" {
			req.SourceAdapter = "http-stub"
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
			http.Error(w, "marshal failed", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		key := []byte(strconv.FormatInt(req.EmailID, 10))
		if err := prod.Publish(ctx, key, body, 3); err != nil {
			log.Error().Err(err).Int64("email_id", req.EmailID).Msg("publish emails.raw failed")
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}

		log.Info().Int64("email_id", req.EmailID).Msg("ingested fake email")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "accepted",
			"email_id": req.EmailID,
		})
	}
}
