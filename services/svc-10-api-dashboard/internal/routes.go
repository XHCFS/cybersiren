package api_dashboard

import (
	"net/http"

	sharedauth "github.com/saif/cybersiren/shared/auth"
	"github.com/saif/cybersiren/shared/svckit"

	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/handlers"
	"github.com/saif/cybersiren/services/svc-10-api-dashboard/internal/middleware"
)

// loginOrgID is the single hardcoded tenant (MVP-1) the login flow resolves the
// user against. Post-login org scoping ALWAYS derives from the verified JWT
// claim OrgID, never this constant.
const loginOrgID = 1

// RegisterRoutes is the svckit HTTPRoutes hook for svc-10. It builds the JWT
// manager from shared/config, assembles the console API over the DB pool, and
// mounts the routes onto an inner mux that is wrapped (whole) in CORS for the
// SPA dev origin + a zerolog access log, then bound onto the svckit mux at "/".
//
// Auth boundary: /healthz and POST /api/v1/auth/login are PUBLIC; every other
// /api/v1/* route is behind the Bearer-JWT auth middleware.
func RegisterRoutes(mux *http.ServeMux, deps svckit.Deps) {
	cors := middleware.CORS()
	logMW := middleware.Logger(deps.Log)

	jwtMgr, err := sharedauth.NewManager(deps.Cfg.Auth.JWTSecret, deps.Cfg.Auth.JWTExpiry)
	if err != nil {
		// A broken JWT manager means we cannot issue or verify sessions; fail
		// closed by binding a handler that always 500s rather than serving an
		// unauthenticated API. /healthz stays live so the container is still
		// observable as up-but-degraded.
		deps.Log.Error().Err(err).Msg("jwt manager init failed; console API disabled")
		degraded := http.NewServeMux()
		degraded.HandleFunc("/healthz", healthz)
		degraded.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "auth misconfigured", http.StatusInternalServerError)
		})
		mux.Handle("/", cors(logMW(degraded)))
		return
	}

	scanCfg := LoadScanForwardConfig()
	api := &handlers.API{
		Reader: handlers.NewDBReader(deps.Pool),
		Issuer: jwtMgr,
		Log:    deps.Log,
		OrgID:  loginOrgID,
		Scan:   handlers.NewScanForwarder(scanCfg.ScanURL(), scanCfg.SVC01APIKey, deps.Log),
	}

	// Protected subtree: every route here requires a valid Bearer JWT. Patterns
	// carry their full path because the subtree is mounted at "/api/v1/" and the
	// inner mux sees the original request path.
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/v1/me", api.HandleMe)
	protected.HandleFunc("GET /api/v1/emails", api.HandleListEmails)
	protected.HandleFunc("GET /api/v1/emails/{id}", api.HandleGetEmail)
	protected.HandleFunc("GET /api/v1/rules", api.HandleListRules)
	protected.HandleFunc("GET /api/v1/stats/threats", api.HandleThreatStats)
	protected.HandleFunc("GET /api/v1/stats/campaigns", api.HandleCampaignStats)
	protected.HandleFunc("GET /api/v1/stats/feeds", api.HandleFeedStats)
	protected.HandleFunc("GET /api/v1/stats/rules", api.HandleRuleStats)
	protected.HandleFunc("GET /api/v1/stats/ingestion", api.HandleIngestionStats)
	protected.HandleFunc("POST /api/v1/scan", api.HandleScan)

	authMW := middleware.Auth(jwtMgr)

	// app is the inner mux. Public routes use more-specific patterns than the
	// "/api/v1/" subtree, so Go's ServeMux precedence routes them WITHOUT the
	// auth middleware; everything else under /api/v1/ goes through auth.
	app := http.NewServeMux()
	app.HandleFunc("/healthz", healthz)
	app.HandleFunc("POST /api/v1/auth/login", api.HandleLogin)
	app.Handle("/api/v1/", authMW(protected))

	mux.Handle("/", cors(logMW(app)))
}

// healthz is the public liveness endpoint.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
