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

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/publicsuffix"

	phclient "github.com/saif/cybersiren/internal/phishing/client"
	"github.com/saif/cybersiren/internal/phishing/enricher"
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
	// Log is used for fallback / degraded-mode warnings. The zero value
	// (a noop logger) is fine.
	Log zerolog.Logger
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
	cfg      Config
	client   *phclient.Client
	metrics  *phclient.Metrics
	enricher *enricher.Enricher // nil when GeoIP unavailable; Score falls back to /score
	log      zerolog.Logger
}

// NewDetector creates a Detector from cfg. When cfg.GeoIPDir is set and the
// MaxMind databases load successfully, the detector enriches URLs in-process
// on the Go side and scores them via /score-features. Otherwise it falls
// back to sending the raw URL to the sidecar's /score endpoint (sidecar
// performs its own enrichment).
func NewDetector(cfg Config) (*Detector, error) {
	cfg.withDefaults()
	c, err := phclient.NewClientWithMetrics(cfg.SidecarURL, cfg.Metrics)
	if err != nil {
		return nil, fmt.Errorf("create phishing sidecar client: %w", err)
	}
	// zerolog.Logger zero value has no writer — emit to Nop unless the
	// caller has explicitly disabled their logger (rare).
	logger := cfg.Log
	if logger.GetLevel() == zerolog.NoLevel {
		logger = zerolog.Nop()
	}
	d := &Detector{cfg: cfg, client: c, metrics: cfg.Metrics, log: logger}
	if cfg.GeoIPDir != "" {
		enr, enrErr := enricher.New(cfg.GeoIPDir)
		if enrErr != nil {
			d.log.Warn().Err(enrErr).Str("geoip_dir", cfg.GeoIPDir).
				Msg("Go enricher unavailable; falling back to /score (sidecar enrichment)")
		} else {
			d.enricher = enr
		}
	}
	return d, nil
}

// Close releases enricher resources (MaxMind dbs).
func (d *Detector) Close() {
	if d.enricher != nil {
		d.enricher.Close()
	}
}

// UsesGoEnricher reports whether Score will route through the Go enricher +
// /score-features path (true) or fall back to the sidecar-side /score path
// (false).
func (d *Detector) UsesGoEnricher() bool { return d.enricher != nil }

// Score scores one URL against the L2 fusion sidecar. Path selection:
//
//   - If a Go enricher is available (cfg.GeoIPDir loaded), the URL is
//     enriched in-process and the feature vector is sent to /score-features.
//     This gives per-enricher Jaeger spans on the Go side.
//   - Otherwise, the raw URL is sent to /score and the sidecar performs its
//     own enrichment.
//
// Returns from the LRU cache (keyed on full URL) when available. On error
// the caller should fail-open (treat as benign) for Layer 2.
func (d *Detector) Score(ctx context.Context, rawURL string) (Result, error) {
	ctx, span := detectorTracer.Start(ctx, "phishing.detector.Score",
		trace.WithAttributes(attribute.String("phishing.url", rawURL)),
	)
	defer span.End()

	var (
		scored   phclient.ScoreResult
		cacheHit bool
		err      error
		path     string
	)

	if d.enricher != nil {
		path = "score-features"
		scored, cacheHit, err = d.scoreViaFeatures(ctx, rawURL)
	} else {
		path = "score"
		apexKey := apexFromRawURL(rawURL)
		scored, cacheHit, err = d.client.CachedScore(ctx, rawURL, apexKey)
	}
	span.SetAttributes(attribute.String("phishing.path", path))

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

// scoreViaFeatures runs the Go enricher and POSTs the feature vector to
// /score-features. On enrichment failure it falls back to /score so that a
// transient enricher problem doesn't take down L2 entirely.
func (d *Detector) scoreViaFeatures(ctx context.Context, rawURL string) (phclient.ScoreResult, bool, error) {
	eu, enrichErr := d.enricher.Enrich(ctx, rawURL)
	if enrichErr != nil {
		d.log.Warn().Err(enrichErr).Str("url", rawURL).
			Msg("Go enricher failed; falling back to /score for this request")
		apexKey := apexFromRawURL(rawURL)
		result, hit, err := d.client.CachedScore(ctx, rawURL, apexKey)
		if err != nil {
			return phclient.ScoreResult{}, false, fmt.Errorf("fallback /score: %w", err)
		}
		return result, hit, nil
	}
	result, hit, err := d.client.CachedScoreFeatures(ctx, phclient.FeatureRequest{
		NormalizedURL: eu.ResolvedURL,
		IsShortener:   eu.IsShortener,
		Features:      eu.Features.ToJSON(),
	})
	if err != nil {
		return phclient.ScoreResult{}, false, fmt.Errorf("/score-features: %w", err)
	}
	return result, hit, nil
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
