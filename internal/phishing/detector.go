// Package phishing provides Layer 2 ML phishing detection for the CyberSiren
// URL pipeline. It calls a Python sidecar that performs its own enrichment
// (DNS, WHOIS, TLS, HTTP, GeoIP) and fuses URL-structural and operational-feature
// model scores to produce a phishing verdict.
//
// Usage:
//
//	d, err := phishing.NewDetector(phishing.Config{
//	    SidecarURL: "http://127.0.0.1:8765",
//	})
//	result, err := d.Score(ctx, "https://suspicious-login.example.com/verify")
package phishing

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	phclient "github.com/saif/cybersiren/internal/phishing/client"
)

// Config configures the Detector.
type Config struct {
	// SidecarURL is the base URL of the Python scoring sidecar (default "http://127.0.0.1:8765").
	SidecarURL string
	// GeoIPDir is kept for backwards-compatible config; the v2 sidecar handles GeoIP internally.
	GeoIPDir string
	// Threshold is the deploy_p cutoff for "phishing" verdict (default 0.50).
	Threshold float64
}

func (c *Config) withDefaults() {
	if c.SidecarURL == "" {
		c.SidecarURL = "http://127.0.0.1:8765"
	}
	if c.Threshold == 0 {
		c.Threshold = 0.50
	}
}

// Result is the Layer 2 scoring output for one URL.
type Result struct {
	URL          string
	EffectiveURL string
	URLP         float64
	OpP          float64
	DeployP      float64
	Verdict      string // "phishing" | "benign"
	CacheHit     bool
}

// Detector orchestrates sidecar scoring.
type Detector struct {
	cfg    Config
	client *phclient.Client
}

// NewDetector creates a Detector from cfg.
func NewDetector(cfg Config) (*Detector, error) {
	cfg.withDefaults()
	c, err := phclient.NewClient(cfg.SidecarURL)
	if err != nil {
		return nil, err
	}
	return &Detector{cfg: cfg, client: c}, nil
}

// Close is a no-op; kept for interface compatibility.
func (d *Detector) Close() {}

// Score calls the v2 sidecar with rawURL. The sidecar handles all enrichment.
// Returns from the apex-domain LRU cache when available.
// On error the caller should fail-open (treat as benign) for Layer 2.
func (d *Detector) Score(ctx context.Context, rawURL string) (Result, error) {
	apexKey := apexFromRawURL(rawURL)

	scored, cacheHit, err := d.client.CachedScore(ctx, rawURL, apexKey)
	if err != nil {
		return Result{}, err
	}

	return Result{
		URL:          rawURL,
		EffectiveURL: scored.EffectiveURL,
		URLP:         scored.URLP,
		OpP:          scored.OpP,
		DeployP:      scored.DeployP,
		Verdict:      scored.Verdict,
		CacheHit:     cacheHit,
	}, nil
}

func apexFromRawURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	hostname := strings.ToLower(u.Hostname())
	apex, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err == nil {
		return apex
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}
