// Package api_dashboard wires the svc-10 read-mostly analyst-console HTTP API.
package api_dashboard

import "os"

// svc10EnvPrefix namespaces svc-10-LOCAL environment overrides so they cannot
// collide with shared/config keys. svc-10 deliberately does NOT extend
// shared/config (which is imported by all 11 services) for its two
// scan-forward knobs.
const svc10EnvPrefix = "CYBERSIREN_SVC10__"

// Default scan-forward targets. The svc-01 API key is a SERVER-SIDE secret —
// it forwards uploads on behalf of the logged-in analyst and NEVER reaches the
// browser. The default key is the seeded org-1 demo key (db/seeds/api_key_demo_seed.sql).
const (
	defaultSVC01BaseURL = "http://localhost:8081"
	defaultSVC01APIKey  = "cs_demokey000000000000000000000DEMO"
)

// ScanForwardConfig holds the svc-10-local knobs for the scan-submission proxy.
type ScanForwardConfig struct {
	// SVC01BaseURL is the svc-01 ingestion base URL; the scan handler POSTs to
	// SVC01BaseURL + "/api/v1/scan".
	SVC01BaseURL string
	// SVC01APIKey is the API key svc-10 presents to svc-01 (Bearer). Server-side
	// only — never sent to the SPA.
	SVC01APIKey string
}

// LoadScanForwardConfig reads the scan-forward knobs from the environment,
// falling back to the demo defaults. Reads CYBERSIREN_SVC10__SVC01_BASE_URL and
// CYBERSIREN_SVC10__SVC01_API_KEY.
func LoadScanForwardConfig() ScanForwardConfig {
	return ScanForwardConfig{
		SVC01BaseURL: envOr(svc10EnvPrefix+"SVC01_BASE_URL", defaultSVC01BaseURL),
		SVC01APIKey:  envOr(svc10EnvPrefix+"SVC01_API_KEY", defaultSVC01APIKey),
	}
}

// ScanURL is the full svc-01 scan endpoint the proxy POSTs to.
func (c ScanForwardConfig) ScanURL() string {
	return c.SVC01BaseURL + "/api/v1/scan"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
