// svc-01-ingestion is the Ingestion Service: the entry point of the pipeline.
// It exposes the API-upload adapter (POST /api/v1/scan), authenticates every
// request against an API key (binding org_id from the key, never the body —
// G10), enforces a 7-day (org, message_id) dedup and a monthly ingestion quota,
// assigns the logical email_id as a UUIDv7 (G17/#142), and publishes emails.raw.
//
// It does NOT write the emails table — svc-02 is the SOLE emails writer (the v0
// INSERT shim is retired). Adapter scope (D2): API-upload + Gmail only; IMAP and
// Outlook are deferred (P2) and are not built here.
//
// See docs/architecture/architecture-spec-detail.html §1 step 1 + §2.1.
package main

import (
	"net/http"
	"os"

	"github.com/rs/zerolog"

	sharedauth "github.com/saif/cybersiren/shared/auth"
	contracts "github.com/saif/cybersiren/shared/contracts/kafka"
	"github.com/saif/cybersiren/shared/svckit"

	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/auth"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/dedup"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/ingest"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/pgstore"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/quota"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/source/apiupload"
)

const serviceName = "svc-01-ingestion"

func main() {
	if err := svckit.Run(svckit.Spec{
		Name:           serviceName,
		NeedsDB:        true,
		NeedsValkey:    true,
		ProducerTopics: []string{contracts.TopicEmailsRaw},
		HTTPPort:       8081,
		// HTTPRoutes runs after the pool, Valkey client, and producers are wired
		// (svckit.Run order), so the full app is assembled here.
		HTTPRoutes: registerRoutes,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// registerRoutes assembles the ingestion app from svckit deps and binds the
// API-upload adapter behind the API-key auth middleware.
func registerRoutes(mux *http.ServeMux, deps svckit.Deps) {
	// KeyManager knows the lookup-prefix length + validation rules from config.
	km, err := sharedauth.NewKeyManager(
		deps.Cfg.Auth.APIKeyPrefix,
		deps.Cfg.Auth.APIKeyPrefixLen,
		deps.Cfg.Auth.BcryptCost,
	)
	if err != nil {
		// A misconfigured KeyManager mints/validates keys incorrectly; fail
		// closed by binding a handler that always 500s rather than ingesting
		// with broken auth.
		deps.Log.Error().Err(err).Msg("api-key manager init failed; /api/v1/scan disabled")
		mux.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "auth misconfigured", http.StatusInternalServerError)
		})
		return
	}

	authn := auth.NewAuthenticator(pgstore.NewKeyStore(deps.Pool), km, deps.Log)

	core := ingest.NewCore(ingest.Config{
		Dedup:    dedup.New(deps.Valkey, deps.Pool),
		Quota:    quota.New(deps.Valkey),
		Orgs:     pgstore.NewOrgStore(deps.Pool),
		Producer: deps.Producers[contracts.TopicEmailsRaw],
		Log:      deps.Log,
	})

	adapter := apiupload.New(core, deps.Log)

	// Build the adapter's routes on a private mux, then wrap the whole thing in
	// the auth middleware so every /api/v1/* route requires a valid API key.
	adapterMux := http.NewServeMux()
	adapter.Register(adapterMux)
	mux.Handle("/api/v1/", authn.Middleware(adapterMux))
}
