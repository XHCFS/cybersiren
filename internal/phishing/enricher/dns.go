package enricher

import (
	"context"
	"errors"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.opentelemetry.io/otel/attribute"
)

const (
	// dnsCacheMaxEntries bounds the in-process DNS cache so attacker-controlled
	// hostnames (one per URL in incoming email) cannot grow it without limit.
	dnsCacheMaxEntries = 10_000
	// dnsCacheTTL bounds staleness (DNS records change); dnsNegativeTTL keeps a
	// transient resolution failure from being cached for the whole TTL.
	dnsCacheTTL    = 10 * time.Minute
	dnsNegativeTTL = 1 * time.Minute
)

type dnsEntry struct {
	ip        string
	expiresAt time.Time
}

type dnsCache struct {
	lru *lru.Cache[string, dnsEntry]
}

func newDNSCache() *dnsCache {
	l, _ := lru.New[string, dnsEntry](dnsCacheMaxEntries)
	return &dnsCache{lru: l}
}

func (c *dnsCache) get(host string) (string, bool) {
	e, ok := c.lru.Get(host)
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.ip, true
}

func (c *dnsCache) set(host, ip string, ttl time.Duration) {
	c.lru.Add(host, dnsEntry{ip: ip, expiresAt: time.Now().Add(ttl)})
}

var globalDNSCache = newDNSCache()

// ResolveIP resolves hostname to an IPv4 address (preferred) or IPv6 address.
// Results are cached in-process for the binary lifetime. Returns empty string on failure.
func ResolveIP(ctx context.Context, hostname string) string {
	ip, _ := resolveIPStatus(ctx, hostname)
	return ip
}

// resolveIPStatus is ResolveIP plus a signal of whether a failed lookup was a
// network-level error (timeout / SERVFAIL — the resolver could not be reached)
// as opposed to a clean negative answer (NXDOMAIN / no addresses — the host
// genuinely does not exist while the network is healthy).
//
// The distinction matters for the L2 circuit breaker: a sustained run of
// network errors means enrichment cannot run and the breaker should trip
// (fail-open + Degraded so recall is preserved), whereas a deregistered/dead
// domain is a normal, expected negative that must NOT trip the breaker — those
// benign dead-domain URLs are exactly what the de-escalation path is meant to
// clear. A cache hit reports netErr=false (cached negatives are clean answers).
func resolveIPStatus(ctx context.Context, hostname string) (ip string, netErr bool) {
	ctx, span := enricherTracer.Start(ctx, "enricher.dns.ResolveIP")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.hostname", hostname))

	if ip, ok := globalDNSCache.get(hostname); ok {
		span.SetAttributes(attribute.Bool("enricher.cache_hit", true), attribute.String("enricher.ip", ip))
		return ip, false
	}
	span.SetAttributes(attribute.Bool("enricher.cache_hit", false))

	lookupCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, hostname)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			span.RecordError(err)
			netErr = isDNSNetworkError(err)
			span.SetAttributes(attribute.Bool("enricher.dns_network_error", netErr))
		}
		globalDNSCache.set(hostname, "", dnsNegativeTTL)
		return "", netErr
	}

	var result string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			result = addr
			break
		}
		if result == "" {
			result = addr
		}
	}

	globalDNSCache.set(hostname, result, dnsCacheTTL)
	span.SetAttributes(attribute.String("enricher.ip", result))
	return result, false
}

// isDNSNetworkError reports whether a resolver error indicates the network/DNS
// infrastructure could not be reached (timeout, SERVFAIL, connection refused),
// as opposed to a definitive NXDOMAIN ("no such host"). NXDOMAIN means the host
// does not exist but the network is healthy, so it is NOT a network error.
func isDNSNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// IsNotFound == NXDOMAIN: a clean negative, network is fine.
		return !dnsErr.IsNotFound
	}
	// Non-DNSError (e.g. context deadline exceeded): treat as a network error.
	return true
}
