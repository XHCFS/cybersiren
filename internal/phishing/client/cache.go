package client

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	defaultMaxEntries = 10_000
	defaultTTL        = 5 * time.Minute
)

type cacheEntry struct {
	result    ScoreResult
	expiresAt time.Time
}

// Cache is a thread-safe LRU cache keyed on apex domain with a TTL.
type Cache struct {
	mu  sync.Mutex
	lru *lru.Cache[string, cacheEntry]
	ttl time.Duration
}

// NewCache creates a Cache with up to maxEntries items and the given TTL.
// Use maxEntries=0 for the default (10,000). Use ttl=0 for the default (5 min).
func NewCache(maxEntries int, ttl time.Duration) (*Cache, error) {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}
	l, err := lru.New[string, cacheEntry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &Cache{lru: l, ttl: ttl}, nil
}

// Get returns the cached result for key and whether it was found and still valid.
func (c *Cache) Get(key string) (ScoreResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.lru.Get(key)
	if !ok || time.Now().After(e.expiresAt) {
		return ScoreResult{}, false
	}
	return e.result, true
}

// Set stores result under key with the configured TTL.
func (c *Cache) Set(key string, result ScoreResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Add(key, cacheEntry{result: result, expiresAt: time.Now().Add(c.ttl)})
}

// Len returns the number of entries currently in the LRU. Reports both fresh
// and expired entries (lazy-expiry); good enough for a metric gauge.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
