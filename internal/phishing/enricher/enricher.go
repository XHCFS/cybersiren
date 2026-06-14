package enricher

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"
)

// EnrichedURL holds the raw and resolved URL plus all enrichment results.
type EnrichedURL struct {
	OriginalURL string
	ResolvedURL string // set when shortener resolved to a different apex; else == OriginalURL
	IsShortener bool

	IP    string
	WHOIS WHOISResult
	Geo   GeoIPResult
	TLS   TLSResult
	HTTP  HTTPResult

	Features FeatureVector
}

// Enricher orchestrates all enrichment steps concurrently.
type Enricher struct {
	geoIPDir string
	geo      *GeoIPLookup
}

// New creates an Enricher and opens the MaxMind databases from geoIPDir.
func New(geoIPDir string) (*Enricher, error) {
	geo, err := NewGeoIPLookup(geoIPDir)
	if err != nil {
		return nil, err
	}
	return &Enricher{geoIPDir: geoIPDir, geo: geo}, nil
}

// Close releases MaxMind database resources.
func (e *Enricher) Close() {
	if e.geo != nil {
		e.geo.Close()
	}
}

// enricherTimeout bounds the whole enrichment operation. Lowered from 8s: the
// per-email URL loop now runs these concurrently with a tight per-URL budget,
// and the two slow legs (WHOIS, HTTP) are themselves capped at ~1.5-2s, so a
// 2s overall cap keeps the worst-case per-URL latency near that of the slowest
// single leg rather than letting one host stall the whole email.
const enricherTimeout = 2 * time.Second

// Enrich runs enrichment for one URL. DNS resolution runs FIRST as a gate: if
// the host does not resolve (NXDOMAIN / no A or AAAA), the expensive WHOIS and
// HTTP-GET legs are skipped entirely — you can't fetch a dead host, and most
// phishing domains are already taken down by the time the email is scored. The
// remaining cheap legs (GeoIP needs the IP anyway; TLS) still run when there is
// an IP. The whole operation is bounded by enricherTimeout.
func (e *Enricher) Enrich(ctx context.Context, rawURL string) (EnrichedURL, error) {
	ctx, span := enricherTracer.Start(ctx, "enricher.Enrich")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.url", rawURL))

	ctx, cancel := context.WithTimeout(ctx, enricherTimeout)
	defer cancel()

	eu := EnrichedURL{OriginalURL: rawURL}

	// Shortener resolution
	if IsShortener(rawURL) {
		eu.IsShortener = true
		resolved, _ := ResolveShortURL(ctx, rawURL)
		if resolved != "" {
			eu.ResolvedURL = resolved
		} else {
			eu.ResolvedURL = rawURL
		}
	} else {
		eu.ResolvedURL = rawURL
	}

	effectiveURL := eu.ResolvedURL
	hostname := extractHostname(effectiveURL)
	apex := apexDomain(hostname)

	// DNS gate: resolve first. A dead host short-circuits the two 5s legs.
	eu.IP = ResolveIP(ctx, hostname)
	span.SetAttributes(attribute.Bool("enricher.resolved", eu.IP != ""))

	if eu.IP == "" {
		// Host does not resolve: skip WHOIS + HTTP (and TLS, which also needs a
		// reachable host). Return with whatever cheap signal exists. Features
		// computed from the zero-value WHOIS/HTTP/TLS correctly read as "unknown".
		span.SetAttributes(attribute.Bool("enricher.dns_gate_skip", true))
		eu.Features = ComputeFeatures(eu)
		return eu, nil
	}

	g, gctx := errgroup.WithContext(ctx)

	// GeoIP (DNS already delivered the IP). GeoIPLookup.Lookup has no ctx of its
	// own, so wrap it in a span here for trace continuity.
	g.Go(func() error {
		_, geoSpan := enricherTracer.Start(gctx, "enricher.geoip.Lookup")
		geoSpan.SetAttributes(attribute.String("enricher.ip", eu.IP))
		eu.Geo = e.geo.Lookup(eu.IP)
		geoSpan.SetAttributes(
			attribute.String("enricher.country", eu.Geo.Country),
			attribute.Int64("enricher.asn", int64(eu.Geo.ASN)),
		)
		geoSpan.End()
		return nil
	})

	// WHOIS
	g.Go(func() error {
		eu.WHOIS = LookupWHOIS(gctx, apex)
		return nil
	})

	// TLS
	g.Go(func() error {
		eu.TLS = GetTLSCert(gctx, hostname, 443)
		return nil
	})

	// HTTP
	g.Go(func() error {
		eu.HTTP = FetchHTTP(gctx, effectiveURL)
		return nil
	})

	// Ignore context-cancellation errors — enrichment degrades gracefully.
	if err := g.Wait(); err != nil && gctx.Err() == nil {
		return eu, fmt.Errorf("enrich %q: %w", rawURL, err)
	}

	eu.Features = ComputeFeatures(eu)
	return eu, nil
}

func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
