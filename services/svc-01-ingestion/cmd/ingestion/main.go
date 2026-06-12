// svc-01-ingestion is the Ingestion Service: the entry point of the pipeline.
// It exposes the API-upload adapter (POST /api/v1/scan) AND the Gmail adapter
// (Pub/Sub push at POST /gmail/push + a fallback poll loop), authenticates API
// requests against an API key (binding org_id from the key, never the body —
// G10), enforces a 7-day (org, message_id) dedup and a monthly ingestion quota,
// assigns the logical email_id as a UUIDv7 (G17/#142), and publishes emails.raw.
// Both adapters share the same ingestion core, so dedup/quota/UUIDv7 apply
// uniformly regardless of source.
//
// It does NOT write the emails table — svc-02 is the SOLE emails writer (the v0
// INSERT shim is retired). Adapter scope (D2): API-upload + Gmail only; IMAP and
// Outlook are deferred (P2) and are not built here.
//
// See docs/architecture/architecture-spec-detail.html §1 step 1 + §2.1.
package main

import (
	"context"
	"encoding/json"
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
	gmailsrc "github.com/saif/cybersiren/services/svc-01-ingestion/internal/source/gmail"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/verdict"
	"github.com/saif/cybersiren/services/svc-01-ingestion/internal/webui"
)

const serviceName = "svc-01-ingestion"

// gmailAdapter is the optional Gmail adapter, built once in registerRoutes (so
// its push route is bound) and reused in onReady (to start its watch/poll/renew
// loops). It is nil when the Gmail adapter is disabled in config. Assigned
// exactly once before the consumer loop starts and only read afterward, so no
// synchronisation is required.
var gmailAdapter *gmailsrc.Adapter

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
		// OnReady starts the Gmail watch/poll/renew loops once everything is up.
		OnReady: onReady,
	}); err != nil {
		l := zerolog.New(os.Stderr)
		l.Error().Err(err).Send()
		os.Exit(1)
	}
}

// registerRoutes assembles the ingestion app from svckit deps and binds the
// API-upload adapter behind the API-key auth middleware plus, when enabled, the
// Gmail Pub/Sub push endpoint.
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

	// Demo-UI verdict reads (GET /verdict, /verdict/latest). Wrapped in the SAME
	// API-key middleware as /api/v1/scan: the reads hit FORCE-RLS tables and so
	// need an org context (WithOrgTx), and the demo key already grants
	// verdict:read. The bundled page prefills that key, so it stays one-click.
	verdictMux := http.NewServeMux()
	verdict.New(deps.Pool, deps.Log).Register(verdictMux)
	mux.Handle("/verdict", authn.Middleware(verdictMux))
	mux.Handle("/verdict/", authn.Middleware(verdictMux))

	// Same-origin demo UI (B4): a single self-contained page that drives both
	// ingestion paths. Served by svc-01 itself so there is no CORS surface. Not a
	// production feature — a demo affordance for real users.
	registerDemoUI(mux, deps)

	// Gmail adapter (optional). It shares the SAME ingestion core as the API
	// adapter, so dedup/quota/UUIDv7 apply identically. The push endpoint is
	// NOT behind the API-key middleware — its own verifyPush gate (shared token
	// / OIDC audience) authenticates Google's Pub/Sub push instead.
	ga, gerr := gmailsrc.Build(deps.Cfg.Gmail, core, deps.Valkey, deps.Log)
	if gerr != nil {
		deps.Log.Error().Err(gerr).Msg("gmail adapter init failed; Gmail ingestion disabled")
		return
	}
	if ga != nil {
		gmailAdapter = ga
		if gmailsrc.PushEnabled(deps.Cfg.Gmail) {
			ga.Register(mux)
			deps.Log.Info().Msg("gmail push endpoint registered at POST /gmail/push")
		}
	}
}

// registerDemoUI serves the bundled same-origin demo page and a tiny,
// config-derived Gmail status endpoint the page polls. Same-origin means the
// browser talks only to svc-01 — there is no CORS to configure. The assets are
// embedded (see internal/webui), so serving is independent of the working dir.
func registerDemoUI(mux *http.ServeMux, deps svckit.Deps) {
	ui := webui.FS()

	// GET / serves the single-page app. The stdlib ServeMux routes every
	// unmatched path to "/", so guard it to the exact root and 404 the rest
	// (the page is self-contained — there are no other top-level routes).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(w, r, ui, "index.html")
	})

	// Assets (none today — the page is inline — but wired so future split-out
	// CSS/JS is served same-origin with correct content types).
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(ui)))

	// GET /gmail/status reports whether the Gmail adapter is wired, and how
	// (push vs poll), plus the watched mailbox. It exposes NO tenant data — only
	// configuration toggles — so it needs no auth. The B3 runbook flips these on.
	mux.HandleFunc("/gmail/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		g := deps.Cfg.Gmail
		status := map[string]any{
			"enabled": g.Enabled,
			"push":    gmailsrc.PushEnabled(g),
			"poll":    gmailsrc.PollEnabled(g),
			"mailbox": g.User,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
}

// onReady starts the Gmail background loops (watch registration + 24h renewal,
// and the fallback poll loop) after all clients are wired. It is a no-op when
// the Gmail adapter is disabled.
func onReady(ctx context.Context, deps svckit.Deps) error {
	if gmailAdapter == nil {
		return nil
	}
	if gmailsrc.PushEnabled(deps.Cfg.Gmail) {
		// Register the watch so Gmail starts pushing; seed the history cursor.
		// A failure here is non-fatal — the poll loop still recovers mail, and
		// the renewer retries — so we log rather than abort startup.
		if _, err := gmailAdapter.Watch(ctx); err != nil {
			deps.Log.Error().Err(err).Msg("gmail: initial watch failed (poll loop will still run)")
		}
		go gmailAdapter.RunWatchRenewer(ctx)
	}
	if gmailsrc.PollEnabled(deps.Cfg.Gmail) {
		go gmailAdapter.RunPollLoop(ctx)
	}
	return nil
}
