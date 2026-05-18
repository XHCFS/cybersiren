package enricher

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

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

// Enrich runs all enrichment steps concurrently for one URL.
// The whole operation is bounded by an 8-second timeout.
func (e *Enricher) Enrich(ctx context.Context, rawURL string) (EnrichedURL, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
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

	g, gctx := errgroup.WithContext(ctx)

	// DNS + GeoIP (sequential: GeoIP needs the IP)
	ipCh := make(chan string, 1)
	g.Go(func() error {
		ip := ResolveIP(gctx, hostname)
		eu.IP = ip
		ipCh <- ip
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

	// GeoIP (starts after DNS delivers the IP)
	g.Go(func() error {
		select {
		case ip := <-ipCh:
			if ip != "" {
				eu.Geo = e.geo.Lookup(ip)
			}
		case <-gctx.Done():
		}
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
