package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// HandleListEmails returns a paginated page of the org's emails (newest first).
func (a *API) HandleListEmails(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit, offset, ok := paginate(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("limit and offset must be non-negative integers"))
		return
	}

	items, err := a.Reader.ListEmails(r.Context(), claims.OrgID, limit, offset)
	if err != nil {
		a.Log.Error().Err(err).Int64("org_id", claims.OrgID).Msg("list emails failed")
		writeJSON(w, http.StatusInternalServerError, errBody("could not list emails"))
		return
	}
	if items == nil {
		items = []EmailListItem{}
	}
	writeJSON(w, http.StatusOK, Page[EmailListItem]{
		Items:  items,
		Limit:  limit,
		Offset: offset,
		Count:  len(items),
	})
}

// HandleGetEmail returns the composite detail for one email by its logical
// UUIDv7 email_id (path value {id}).
func (a *API) HandleGetEmail(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errBody("email id is required"))
		return
	}

	detail, err := a.Reader.GetEmailDetail(r.Context(), claims.OrgID, id)
	if errors.Is(err, ErrNotFound) {
		writeJSON(w, http.StatusNotFound, errBody("email not found"))
		return
	}
	if err != nil {
		a.Log.Error().Err(err).Int64("org_id", claims.OrgID).Str("email_id", id).Msg("get email detail failed")
		writeJSON(w, http.StatusInternalServerError, errBody("could not load email"))
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// HandleListRules returns the read-only rules list for the org.
func (a *API) HandleListRules(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rules, err := a.Reader.ListRules(r.Context(), claims.OrgID)
	if err != nil {
		a.Log.Error().Err(err).Int64("org_id", claims.OrgID).Msg("list rules failed")
		writeJSON(w, http.StatusInternalServerError, errBody("could not list rules"))
		return
	}
	if rules == nil {
		rules = []RuleSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// paginate parses limit/offset query params with sane defaults and bounds.
// Returns ok=false on a malformed (non-integer or negative) value.
func paginate(r *http.Request) (limit, offset int, ok bool) {
	limit = defaultLimit
	offset = 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		offset = n
	}
	if limit == 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit, offset, true
}
