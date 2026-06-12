// Command dashboard is a STANDALONE, throwaway demo UI for the CyberSiren
// pipeline. It is deliberately decoupled from the services: it talks to the
// pipeline only from the OUTSIDE — forwarding .eml uploads and Gmail messages to
// svc-01's POST /api/v1/scan, and consuming emails.scored / emails.verdict to
// render the per-module scoring breakdown. It owns no spec responsibility and is
// a stand-in for the eventual svc-10 dashboard; delete demo/ to remove it.
package main

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

//go:embed web
var webFS embed.FS

type config struct {
	Addr         string
	KafkaBrokers string
	SVC01ScanURL string
	DemoAPIKey   string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	GmailPollInterval  time.Duration
	TokenFile          string
	StoreFile          string
}

func loadConfig() config {
	return config{
		Addr:               env("DEMO_ADDR", ":8090"),
		KafkaBrokers:       env("KAFKA_BROKERS", "localhost:9092"),
		SVC01ScanURL:       env("SVC01_SCAN_URL", "http://localhost:8081/api/v1/scan"),
		DemoAPIKey:         env("DEMO_API_KEY", "cs_demokey000000000000000000000DEMO"),
		GoogleClientID:     env("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: env("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  env("GOOGLE_REDIRECT_URL", "http://localhost:8090/oauth/callback"),
		GmailPollInterval:  envDur("GMAIL_POLL_INTERVAL", time.Minute),
		TokenFile:          env("GMAIL_TOKEN_FILE", ""),
		StoreFile:          env("DEMO_STORE_FILE", "demo/dashboard/.scans.json"),
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envDur(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if p, err := time.ParseDuration(v); err == nil {
			return p
		}
	}
	return d
}

// loadDotenv loads KEY=VALUE pairs from an optional .env file (default
// demo/dashboard/.env, override via DEMO_ENV_FILE) into the process environment.
// Real environment variables always win — a value already set is never
// overwritten. Blank lines and #-comments are skipped; an optional leading
// "export " and surrounding quotes on the value are stripped. A missing file is
// fine (the demo just runs with defaults / whatever is already exported).
func loadDotenv() {
	path := env("DEMO_ENV_FILE", "demo/dashboard/.env")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k == "" {
			continue
		}
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}

func main() {
	loadDotenv()
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Str("service", "demo-dashboard").Logger()
	cfg := loadConfig()
	st := newStore(200, cfg.StoreFile)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go st.runFlusher(ctx)

	startConsumers(ctx, cfg, st, log)

	gm := newGmail(cfg, st, log)
	gm.resume(ctx)

	mux := http.NewServeMux()
	registerRoutes(mux, cfg, st, gm, log)

	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()

	log.Info().Str("addr", cfg.Addr).Str("svc01", cfg.SVC01ScanURL).
		Bool("gmail_configured", cfg.GoogleClientID != "").Msg("demo dashboard listening")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("server failed")
	}
}

// uiFS returns the filesystem the dashboard serves its HTML/JS from. By
// default it is the copy embedded into the binary at build time. Set DEMO_DEV=1
// to serve demo/dashboard/web straight from disk instead, so HTML/JS edits show
// up on a plain browser refresh with no rebuild or restart. Falls back to the
// embedded assets if the directory can't be found (e.g. the process was not
// started from the repo root).
func uiFS(log zerolog.Logger) fs.FS {
	if os.Getenv("DEMO_DEV") != "" {
		const dir = "demo/dashboard/web"
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			log.Info().Str("dir", dir).Msg("DEMO_DEV: serving UI from disk (edit + refresh, no rebuild)")
			return os.DirFS(dir)
		}
		log.Warn().Msg("DEMO_DEV set but demo/dashboard/web not found from CWD; using embedded assets")
	}
	sub, _ := fs.Sub(webFS, "web")
	return sub
}

func registerRoutes(mux *http.ServeMux, cfg config, st *store, gm *gmailConnector, log zerolog.Logger) {
	ui := uiFS(log)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, ui, "index.html")
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(ui)))

	h := &handlers{cfg: cfg, st: st, gm: gm, log: log, client: &http.Client{Timeout: 30 * time.Second}}
	mux.HandleFunc("/api/scan", h.handleScan)
	mux.HandleFunc("/api/verdict", h.handleVerdict)
	mux.HandleFunc("/api/scans", h.handleScans)
	mux.HandleFunc("/api/gmail/status", h.handleGmailStatus)

	mux.HandleFunc("/gmail/connect", gm.handleConnect)
	mux.HandleFunc("/oauth/callback", gm.handleCallback)
	mux.HandleFunc("/gmail/disconnect", gm.handleDisconnect)
}
