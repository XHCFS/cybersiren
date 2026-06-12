package verdict

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// writeJSON renders v as a JSON body with the given status. A marshal failure is
// logged by the caller's path indirectly — here we just best-effort the encode,
// since the response header may already be committed.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// int4Ptr returns a *int32 from a pgtype.Int4's validity + value, so an absent
// risk_score serialises as JSON null (the email is not yet scored) rather than 0
// (a real, low-risk score) — the UI distinguishes the two.
func int4Ptr(valid bool, v int32) *int32 {
	if !valid {
		return nil
	}
	out := v
	return &out
}

// float8Ptr maps a nullable confidence to a *float64 (null when absent).
func float8Ptr(f pgtype.Float8) *float64 {
	if !f.Valid {
		return nil
	}
	out := f.Float64
	return &out
}

// textOrEmpty unwraps a pgtype.Text to "" when NULL.
func textOrEmpty(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// tsOrEmpty renders a nullable timestamp as RFC 3339, "" when NULL.
func tsOrEmpty(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.UTC().Format(time.RFC3339)
}

// uuidOrEmpty renders a pgtype.UUID as its canonical string, "" when NULL.
func uuidOrEmpty(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}
