// Package verdict is svc-01's demo-UI read side: two small, tenant-scoped
// GET endpoints the bundled static page polls so a real user can watch an
// uploaded email turn into a scored verdict.
//
//   - GET /verdict?email_id=<uuid> resolves the opaque logical email_id back to
//     the canonical (internal_id, fetched_at) partition key via email_identities
//     (migration 035), then reads current_verdicts + emails.risk_score.
//   - GET /verdict/latest returns the most-recent verdicted email for the org —
//     the Gmail panel's "latest verdict" once Gmail is the live source.
//
// Both run behind the SAME API-key middleware as /api/v1/scan: the read needs an
// org for RLS (the queries hit FORCE-RLS tables, so they MUST run inside
// WithOrgTx with the org GUC set — G10/D12), and the demo key already carries a
// verdict:read scope. The UI prefills the demo key, so this is invisible to the
// user. org is taken from the authenticated principal, NEVER from the request.
package verdict

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	db "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
	"github.com/saif/cybersiren/shared/postgres/pgconv"
	"github.com/saif/cybersiren/shared/postgres/repository"
)

// Handler serves the demo-UI verdict reads over the service pool.
type Handler struct {
	pool *pgxpool.Pool
	log  zerolog.Logger
}

// New builds a verdict Handler over the Postgres pool.
func New(pool *pgxpool.Pool, log zerolog.Logger) *Handler {
	return &Handler{pool: pool, log: log}
}

// Register binds the demo read routes. Both expect to be wrapped by the API-key
// auth middleware so the principal (org) is on the context.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/verdict", h.handleByEmailID)
	mux.HandleFunc("/verdict/latest", h.handleLatest)
}

// verdictResponse is the demo-UI JSON shape. status distinguishes the poll
// states the UI loops on: "pending" (email known, no verdict yet) vs "scored".
type verdictResponse struct {
	Status       string   `json:"status"`
	EmailID      string   `json:"email_id,omitempty"`
	Label        string   `json:"label,omitempty"`
	RiskScore    *int32   `json:"risk_score,omitempty"`
	Confidence   *float64 `json:"confidence,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	ModelVersion string   `json:"model_version,omitempty"`
	VerdictAt    string   `json:"verdict_at,omitempty"`
}

func (h *Handler) handleByEmailID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rawID := r.URL.Query().Get("email_id")
	if rawID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email_id is required"})
		return
	}
	if _, err := uuid.Parse(rawID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email_id must be a UUID"})
		return
	}

	resp, status, err := h.lookupByEmailID(r.Context(), principal.OrgID, rawID)
	if err != nil {
		h.log.Error().Err(err).Int64("org_id", principal.OrgID).Str("email_id", rawID).Msg("verdict lookup failed")
		http.Error(w, "verdict lookup failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, status, resp)
}

// lookupByEmailID resolves email_id -> (internal_id, fetched_at) -> verdict, all
// inside one org-scoped transaction so RLS gates every row to the tenant. It
// returns a "pending" response (HTTP 200) for a known-but-unscored email so the
// UI can keep polling, and 404 when the email_id is unknown to this org.
func (h *Handler) lookupByEmailID(ctx context.Context, orgID int64, emailID string) (verdictResponse, int, error) {
	var (
		resp   verdictResponse
		status = http.StatusOK
	)
	err := repository.WithOrgTx(ctx, h.pool, orgID, func(q *db.Queries) error {
		ident, err := q.GetEmailIdentityByEmailID(ctx, db.GetEmailIdentityByEmailIDParams{
			OrgID:   orgID,
			EmailID: pgconv.UUIDOrNull(emailID),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// The email_id is not (yet) registered for this org. svc-02 stamps it
			// only after it parses + persists, so this is the normal early-poll
			// state right after upload — report "pending", not "not found".
			resp = verdictResponse{Status: "pending", EmailID: emailID}
			return nil
		}
		if err != nil {
			return fmt.Errorf("resolve email_id: %w", err)
		}

		v, err := q.GetEmailVerdict(ctx, db.GetEmailVerdictParams{
			InternalID: ident.InternalID,
			FetchedAt:  ident.FetchedAt,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// Parsed but not yet scored by the Decision Engine — keep polling.
			resp = verdictResponse{Status: "pending", EmailID: emailID}
			return nil
		}
		if err != nil {
			return fmt.Errorf("read email verdict: %w", err)
		}

		resp = verdictResponse{
			Status:       "scored",
			EmailID:      emailID,
			Label:        string(v.Label),
			RiskScore:    int4Ptr(v.RiskScore.Valid, v.RiskScore.Int32),
			Confidence:   float8Ptr(v.Confidence),
			ModelVersion: textOrEmpty(v.ModelVersion),
			VerdictAt:    tsOrEmpty(v.VerdictAt),
		}
		return nil
	})
	if err != nil {
		return verdictResponse{}, http.StatusInternalServerError, fmt.Errorf("verdict tx: %w", err)
	}
	return resp, status, nil
}

func (h *Handler) handleLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var resp verdictResponse
	err := repository.WithOrgTx(r.Context(), h.pool, principal.OrgID, func(q *db.Queries) error {
		row, err := q.GetLatestEmailVerdictForOrg(r.Context(), pgconv.Int8(principal.OrgID))
		if errors.Is(err, pgx.ErrNoRows) {
			resp = verdictResponse{Status: "none"}
			return nil
		}
		if err != nil {
			return fmt.Errorf("read latest verdict: %w", err)
		}
		resp = verdictResponse{
			Status:     "scored",
			EmailID:    uuidOrEmpty(row.EmailID),
			Label:      string(row.Label),
			RiskScore:  int4Ptr(row.RiskScore.Valid, row.RiskScore.Int32),
			Confidence: float8Ptr(row.Confidence),
			Subject:    textOrEmpty(row.Subject),
			VerdictAt:  tsOrEmpty(row.VerdictAt),
		}
		return nil
	})
	if err != nil {
		h.log.Error().Err(err).Int64("org_id", principal.OrgID).Msg("latest-verdict lookup failed")
		http.Error(w, "verdict lookup failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
