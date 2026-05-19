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
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/publicsuffix"

	phclient "github.com/saif/cybersiren/internal/phishing/client"
)

var detectorTracer = otel.Tracer("svc-03-url-analysis/phishing-detector")

// DefaultThreshold is the canonical deploy_p cutoff used across the Go
// detector, the Python sidecar default, and the UI red-band threshold.
// Keep these in sync.
const DefaultThreshold = 0.50

// Config configures the Detector.
type Config struct {
	// SidecarURL is the base URL of the Python scoring sidecar (default "http://127.0.0.1:8765").
	SidecarURL string
	// GeoIPDir is kept for backwards-compatible config; the v2 sidecar handles GeoIP internally.
	GeoIPDir string
	// Threshold is the deploy_p cutoff above which Score reclassifies the
	// sidecar verdict as "phishing" (default DefaultThreshold). Allows the
	// Go side to apply a stricter or laxer cutoff than the sidecar.
	Threshold float64
	// Metrics, if non-nil, is passed to the underlying client so cache and
	// sidecar-call counters are recorded. Score increments verdict / cache
	// counters via this holder.
	Metrics *phclient.Metrics
}

func (c *Config) withDefaults() {
	if c.SidecarURL == "" {
		c.SidecarURL = "http://127.0.0.1:8765"
	}
	if c.Threshold == 0 {
		c.Threshold = DefaultThreshold
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
	cfg     Config
	client  *phclient.Client
	metrics *phclient.Metrics
}

// NewDetector creates a Detector from cfg.
func NewDetector(cfg Config) (*Detector, error) {
	cfg.withDefaults()
	c, err := phclient.NewClientWithMetrics(cfg.SidecarURL, cfg.Metrics)
	if err != nil {
		return nil, fmt.Errorf("create phishing sidecar client: %w", err)
	}
	return &Detector{cfg: cfg, client: c, metrics: cfg.Metrics}, nil
}

// Close is a no-op; kept for interface compatibility.
func (d *Detector) Close() {}

// Score calls the v2 sidecar with rawURL. The sidecar handles all enrichment.
// Returns from the apex-domain LRU cache when available.
// On error the caller should fail-open (treat as benign) for Layer 2.
func (d *Detector) Score(ctx context.Context, rawURL string) (Result, error) {
	ctx, span := detectorTracer.Start(ctx, "phishing.detector.Score",
		trace.WithAttributes(attribute.String("phishing.url", rawURL)),
	)
	defer span.End()

	apexKey := apexFromRawURL(rawURL)

	scored, cacheHit, err := d.client.CachedScore(ctx, rawURL, apexKey)
	if err != nil {
		d.metrics.IncScore("error", "miss")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return Result{}, fmt.Errorf("sidecar score: %w", err)
	}

	// Reapply the Go-side threshold over deploy_p. This lets svc-03 pick its
	// own cutoff (env: CYBERSIREN_PHISHING__THRESHOLD) independent of whatever
	// the sidecar process was started with.
	verdict := "benign"
	if scored.DeployP >= d.cfg.Threshold {
		verdict = "phishing"
	}

	cacheLabel := "miss"
	if cacheHit {
		cacheLabel = "hit"
	}
	d.metrics.IncScore(verdict, cacheLabel)
	span.SetAttributes(
		attribute.String("phishing.verdict", verdict),
		attribute.Float64("phishing.deploy_p", scored.DeployP),
		attribute.Bool("phishing.cache_hit", cacheHit),
	)

	return Result{
		URL:          rawURL,
		EffectiveURL: scored.EffectiveURL,
		URLP:         scored.URLP,
		OpP:          scored.OpP,
		DeployP:      scored.DeployP,
		Verdict:      verdict,
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
