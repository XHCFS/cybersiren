package enricher

import (
	"context"
	"net"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type dnsCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func (c *dnsCache) get(host string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.cache[host]
	return v, ok
}

func (c *dnsCache) set(host, ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[host] = ip
}

var globalDNSCache = &dnsCache{cache: make(map[string]string)}

// ResolveIP resolves hostname to an IPv4 address (preferred) or IPv6 address.
// Results are cached in-process for the binary lifetime. Returns empty string on failure.
func ResolveIP(ctx context.Context, hostname string) string {
	ctx, span := enricherTracer.Start(ctx, "enricher.dns.ResolveIP")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.hostname", hostname))

	if ip, ok := globalDNSCache.get(hostname); ok {
		span.SetAttributes(attribute.Bool("enricher.cache_hit", true), attribute.String("enricher.ip", ip))
		return ip
	}
	span.SetAttributes(attribute.Bool("enricher.cache_hit", false))

	lookupCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, hostname)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			span.RecordError(err)
		}
		globalDNSCache.set(hostname, "")
		return ""
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

	globalDNSCache.set(hostname, result)
	span.SetAttributes(attribute.String("enricher.ip", result))
	return result
}
