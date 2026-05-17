package enricher

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

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
	mu    sync.RWMutex
	cache map[string]whoisEntry
}

func (c *whoisCacheStore) get(domain string) (WHOISResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.cache[domain]
	if !ok || time.Now().After(e.expiresAt) {
		return WHOISResult{}, false
	}
	return e.result, true
}

func (c *whoisCacheStore) set(domain string, result WHOISResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[domain] = whoisEntry{result: result, expiresAt: time.Now().Add(24 * time.Hour)}
}

var globalWHOISCache = &whoisCacheStore{cache: make(map[string]whoisEntry)}

// LookupWHOIS performs a WHOIS lookup for domain.
// Results are cached in-process with a 24h TTL.
// Returns zero-value WHOISResult on any failure — never propagates the error.
func LookupWHOIS(ctx context.Context, domain string) WHOISResult {
	if r, ok := globalWHOISCache.get(domain); ok {
		return r
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type outcome struct {
		r   WHOISResult
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		raw, err := whois.Whois(domain)
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
		globalWHOISCache.set(domain, WHOISResult{})
		return WHOISResult{}
	case res := <-ch:
		if res.err != nil {
			globalWHOISCache.set(domain, WHOISResult{})
			return WHOISResult{}
		}
		globalWHOISCache.set(domain, res.r)
		return res.r
	}
}
