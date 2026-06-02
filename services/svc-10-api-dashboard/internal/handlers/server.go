// Package handlers implements the SVC-10 dashboard HTTP endpoints over the
// org-scoped read queries and the in-memory recent-verdict feed.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
	"github.com/saif/cybersiren/shared/auth"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// Server holds the dependencies shared by all handlers.
type Server struct {
	q      *dbsqlc.Queries
	authn  *auth.Authenticator
	recent func() []contracts.EmailsVerdict
	log    zerolog.Logger
}

// NewServer constructs a Server. recent returns the latest buffered verdicts.
func NewServer(q *dbsqlc.Queries, authn *auth.Authenticator, recent func() []contracts.EmailsVerdict, log zerolog.Logger) *Server {
	return &Server{q: q, authn: authn, recent: recent, log: log}
}

// Health reports liveness (process up; deeper checks can be added later).
func (s *Server) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Stats returns the org's headline counters.
func (s *Server) Stats(c *gin.Context) {
	st, err := s.q.GetOrgStats(c.Request.Context(), orgParam(c))
	if err != nil {
		s.fail(c, "stats query failed", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total": st.Total, "phishing": st.Phishing, "suspicious": st.Suspicious,
		"high_risk": st.HighRisk, "last_24h": st.Last24h,
	})
}

// Campaigns lists the org's recent campaigns.
func (s *Server) Campaigns(c *gin.Context) {
	rows, err := s.q.ListCampaignsByOrg(c.Request.Context(), dbsqlc.ListCampaignsByOrgParams{
		OrgID: orgParam(c), Limit: 50,
	})
	if err != nil {
		s.fail(c, "campaigns query failed", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"campaigns": rows})
}

// RecentVerdicts hands out the in-memory verdict ring (the live-ish feed).
func (s *Server) RecentVerdicts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"verdicts": s.recent()})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// orgParam returns the authenticated org id as a pgtype.Int8 for the queries.
func orgParam(c *gin.Context) pgtype.Int8 {
	return pgtype.Int8{Int64: middleware.OrgID(c), Valid: true}
}

// paging reads page (1-based) and page_size query params, clamped.
func paging(c *gin.Context) (limit, offset int32) {
	limit = int32(atoiDefault(c.Query("page_size"), 25))
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	page := int32(atoiDefault(c.Query("page"), 1))
	if page < 1 {
		page = 1
	}
	return limit, (page - 1) * limit
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func (s *Server) fail(c *gin.Context, msg string, err error) {
	s.log.Error().Err(err).Msg(msg)
	c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
}
