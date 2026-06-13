package handlers

import (
	"net/http"

	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
)

// HandleThreatStats serves mv_threat_summary for the org (+ global TI rows).
func (a *API) HandleThreatStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := a.Reader.ThreatSummary(r.Context(), claims.OrgID)
	if err != nil {
		a.statsError(w, err, "threats")
		return
	}
	if rows == nil {
		rows = []ThreatStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"threats": rows})
}

// HandleCampaignStats serves mv_campaign_summary for the org.
func (a *API) HandleCampaignStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := a.Reader.CampaignSummary(r.Context(), claims.OrgID)
	if err != nil {
		a.statsError(w, err, "campaigns")
		return
	}
	if rows == nil {
		rows = []CampaignStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": rows})
}

// HandleFeedStats serves mv_feed_health (platform-global).
func (a *API) HandleFeedStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := a.Reader.FeedHealth(r.Context(), claims.OrgID)
	if err != nil {
		a.statsError(w, err, "feeds")
		return
	}
	if rows == nil {
		rows = []FeedStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": rows})
}

// HandleRuleStats serves mv_rule_performance for the org (+ global rules).
func (a *API) HandleRuleStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := a.Reader.RulePerformance(r.Context(), claims.OrgID)
	if err != nil {
		a.statsError(w, err, "rules")
		return
	}
	if rows == nil {
		rows = []RuleStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rows})
}

// HandleIngestionStats serves the single mv_org_ingestion_summary row.
func (a *API) HandleIngestionStats(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	row, err := a.Reader.OrgIngestionSummary(r.Context(), claims.OrgID)
	if err != nil {
		a.statsError(w, err, "ingestion")
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (a *API) statsError(w http.ResponseWriter, err error, which string) {
	a.Log.Error().Err(err).Str("stat", which).Msg("stats read failed")
	writeJSON(w, http.StatusInternalServerError, errBody("could not load "+which+" stats"))
}
