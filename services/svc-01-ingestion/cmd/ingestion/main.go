// STUB: replace with real implementation. Accepts a synthetic ingest request
// over HTTP and emits emails.raw. NO Gmail/Outlook/IMAP adapters.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	kafkaproducer "github.com/saif/cybersiren/shared/kafka/producer"
	"github.com/saif/cybersiren/shared/svckit"
)

const serviceName = "svc-01-ingestion"

type ingestRequest struct {
	EmailID       string            `json:"email_id,omitempty"`
	OrgID         string            `json:"org_id,omitempty"`
	MessageID     string            `json:"message_id,omitempty"`
	SourceAdapter string            `json:"source_adapter,omitempty"`
	RawMessageB64 string            `json:"raw_message_b64,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:          serviceName,
		NeedsDB:       true,
		NeedsProducer: true,
		HTTPPort:      8081,
		HTTPRoutes: func(mux *http.ServeMux, deps svckit.Deps) {
			mux.HandleFunc("/ingest", ingestHandler(deps.Producer, deps.Log))
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

		if req.EmailID == "" {
			req.EmailID = uuid.NewString()
		}
		if req.OrgID == "" {
			req.OrgID = "org-stub"
		}
		if req.SourceAdapter == "" {
			req.SourceAdapter = "http-stub"
		}

		payload := contracts.EmailsRaw{
			Meta:          contracts.NewMeta(req.EmailID, req.OrgID),
			SourceAdapter: req.SourceAdapter,
			MessageID:     req.MessageID,
			RawMessageB64: req.RawMessageB64,
			Headers:       req.Headers,
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := prod.Publish(ctx, contracts.TopicEmailsRaw, req.EmailID, payload); err != nil {
			log.Error().Err(err).Str("email_id", req.EmailID).Msg("publish emails.raw failed")
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}

		log.Info().Str("email_id", req.EmailID).Msg("ingested fake email")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "accepted",
			"email_id": req.EmailID,
		})
	}
}
