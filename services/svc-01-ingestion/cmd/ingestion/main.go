// STUB: replace with real implementation. Accepts a synthetic ingest request
// over HTTP, INSERTs the row into the partitioned `emails` table, and emits
// emails.raw. NO Gmail/Outlook/IMAP adapters.
//
// The `emails` insert is what binds the logical email_id used on Kafka to
// the (internal_id, fetched_at) partition key downstream services persist
// against (svc-04 rule_hits, svc-08 verdict + emails score update). Without
// it, svc-08's UPDATE matches 0 rows and the pipeline never emits a verdict.
//
// In v0 the email_id and org_id are int64 BIGINT values (matching
// emails.internal_id / orgs.id), generated from the request when not
// supplied — once the real ingestion path lands the BIGSERIAL emails.id
// from this INSERT will be the authoritative source.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
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
			mux.HandleFunc("/ingest", ingestHandler(deps.Pool, deps.Producers[contracts.TopicEmailsRaw], deps.Log))
		},
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

func ingestHandler(pool *pgxpool.Pool, prod *kafkaproducer.Producer, log zerolog.Logger) http.HandlerFunc {
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

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Insert the row into the partitioned `emails` table BEFORE publishing
		// emails.raw. Downstream services persist against (internal_id,
		// fetched_at) — svc-04 rule_hits FK, svc-08 emails UPDATE + verdict
		// FK — so the row must exist by the time their messages arrive. The
		// publish only fans out after the INSERT commits so we can't ship a
		// Kafka event that points at a non-existent partition row.
		if err := insertEmailRow(ctx, pool, req, now); err != nil {
			log.Error().Err(err).Int64("email_id", req.EmailID).Msg("insert emails row failed")
			http.Error(w, "persist failed", http.StatusInternalServerError)
			return
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

		key := []byte(strconv.FormatInt(req.EmailID, 10))
		// Publish last arg: extra kafka retries after first attempt (see kafka/producer).
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

// insertEmailRow writes a minimal emails row keyed by (internal_id, fetched_at).
// Idempotent: 23505 (unique violation, e.g. retried POST with the same
// EMAIL_ID) is treated as success.
func insertEmailRow(ctx context.Context, pool *pgxpool.Pool, req ingestRequest, fetchedAt time.Time) error {
	if pool == nil {
		return errors.New("svc-01: postgres pool unavailable")
	}
	const q = `
INSERT INTO emails (internal_id, fetched_at, org_id, message_id)
VALUES ($1, $2::timestamptz, $3, $4)
ON CONFLICT (internal_id, fetched_at) DO NOTHING
`
	_, err := pool.Exec(ctx, q,
		req.EmailID,
		pgtype.Timestamptz{Time: fetchedAt, Valid: true},
		pgtype.Int8{Int64: req.OrgID, Valid: req.OrgID > 0},
		pgtype.Text{String: req.MessageID, Valid: req.MessageID != ""},
	)
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		// Concurrent retry won the insert race — treat as success.
		return nil
	}
	return fmt.Errorf("svc-01: insert emails row: %w", err)
}
