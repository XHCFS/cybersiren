package enricher

import (
	"context"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"go.opentelemetry.io/otel/attribute"
)

const (
	// whoisCacheMaxEntries bounds the in-process WHOIS cache so attacker-controlled
	// apex domains (one per email) cannot grow it without limit.
	whoisCacheMaxEntries = 10_000
	// whoisSuccessTTL caches a real lookup for a day; whoisNegativeTTL keeps a
	// single timeout/error from poisoning the entry for the full day when a valid
	// WHOIS was retrievable moments later.
	whoisSuccessTTL  = 24 * time.Hour
	whoisNegativeTTL = 5 * time.Minute
	// whoisLookupTimeout bounds the underlying whois.Whois call so the lookup
	// goroutine cannot outlive the caller's budget by the library's ~30s default.
	whoisLookupTimeout = 5 * time.Second
)

// whoisClient is a shared client with a bounded timeout (#40: the library's
// default is ~30s, which lets the lookup goroutine linger long after the 5s
// caller context is done).
var whoisClient = whois.NewClient().SetTimeout(whoisLookupTimeout)

// WHOISResult holds parsed WHOIS data for a domain.
type WHOISResult struct {
	RegistrationDate string
	ExpiryDate       string
	UpdatedDate      string
	Registrar        string
	NameServers      string
}

type whoisEntry struct {
	result    WHOISResult
	expiresAt time.Time
}

type whoisCacheStore struct {
	lru *lru.Cache[string, whoisEntry]
}

func newWHOISCache() *whoisCacheStore {
	l, _ := lru.New[string, whoisEntry](whoisCacheMaxEntries)
	return &whoisCacheStore{lru: l}
}

func (c *whoisCacheStore) get(domain string) (WHOISResult, bool) {
	e, ok := c.lru.Get(domain)
	if !ok || time.Now().After(e.expiresAt) {
		return WHOISResult{}, false
	}
	return e.result, true
}

func (c *whoisCacheStore) set(domain string, result WHOISResult, ttl time.Duration) {
	c.lru.Add(domain, whoisEntry{result: result, expiresAt: time.Now().Add(ttl)})
}

var globalWHOISCache = newWHOISCache()

// LookupWHOIS performs a WHOIS lookup for domain.
// Results are cached in-process with a 24h TTL.
// Returns zero-value WHOISResult on any failure — never propagates the error.
func LookupWHOIS(ctx context.Context, domain string) WHOISResult {
	ctx, span := enricherTracer.Start(ctx, "enricher.whois.LookupWHOIS")
	defer span.End()
	span.SetAttributes(attribute.String("enricher.domain", domain))

	if r, ok := globalWHOISCache.get(domain); ok {
		span.SetAttributes(attribute.Bool("enricher.cache_hit", true))
		return r
	}
	span.SetAttributes(attribute.Bool("enricher.cache_hit", false))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type outcome struct {
		r   WHOISResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		raw, err := whoisClient.Whois(domain)
		if err != nil {
			ch <- outcome{err: err}
			return
		}
		parsed, err := whoisparser.Parse(raw)
		if err != nil {
			ch <- outcome{err: err}
			return
		}
		r := WHOISResult{}
		if parsed.Domain != nil {
			r.RegistrationDate = parsed.Domain.CreatedDate
			r.ExpiryDate = parsed.Domain.ExpirationDate
			r.UpdatedDate = parsed.Domain.UpdatedDate
			r.NameServers = strings.Join(parsed.Domain.NameServers, ",")
		}
		if parsed.Registrar != nil {
			r.Registrar = parsed.Registrar.Name
		}
		ch <- outcome{r: r}
	}()

	select {
	case <-ctx.Done():
		// Timeout/cancel: cache the miss only briefly so one slow lookup doesn't
		// poison the domain for a full day when WHOIS was retrievable.
		globalWHOISCache.set(domain, WHOISResult{}, whoisNegativeTTL)
		return WHOISResult{}
	case res := <-ch:
		if res.err != nil {
			globalWHOISCache.set(domain, WHOISResult{}, whoisNegativeTTL)
			return WHOISResult{}
		}
		globalWHOISCache.set(domain, res.r, whoisSuccessTTL)
		return res.r
	}
}
