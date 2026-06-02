// Package api_dashboard wires the SVC-10 HTTP router: middleware chain +
// public/protected route groups over the dashboard handlers.
package api_dashboard

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	valkeygo "github.com/valkey-io/valkey-go"

	dbsqlc "github.com/saif/cybersiren/db/sqlc"
	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/handlers"
	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
	"github.com/saif/cybersiren/shared/auth"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
)

// apiRatePerMin caps requests per client IP per minute.
const apiRatePerMin = 600

// NewRouter builds the Gin engine. Middleware order: recovery → CORS → logging →
// rate limit → (per-group) auth. recent returns the buffered verdict feed.
func NewRouter(
	pool *pgxpool.Pool,
	vk valkeygo.Client,
	authn *auth.Authenticator,
	recent func() []contracts.EmailsVerdict,
	corsOrigins []string,
	log zerolog.Logger,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	srv := handlers.NewServer(dbsqlc.New(pool), authn, recent, log)

	r := gin.New()
	r.Use(gin.Recovery(), middleware.CORS(corsOrigins), middleware.Logger(log), middleware.RateLimit(vk, log, apiRatePerMin))

	r.GET("/healthz", srv.Health)

	v1 := r.Group("/api/v1")
	v1.POST("/auth/login", srv.Login)

	authed := v1.Group("")
	authed.Use(middleware.RequireJWT(authn))
	authed.GET("/emails", srv.ListEmails)
	authed.GET("/emails/:id", srv.GetEmail)
	authed.GET("/stats", srv.Stats)
	authed.GET("/campaigns", srv.Campaigns)
	authed.GET("/verdicts/recent", srv.RecentVerdicts)

	return r
}
