// Package cache implements an in-memory cache for vulnerability results.
package cache

import (
	"sync"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Memory implements an in-process cache with TTL support.
type Memory struct {
	mu    sync.RWMutex
	items map[string]*cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	vulns     []dependency.Vulnerability
	expiresAt time.Time
}

// New creates a new in-memory cache with the given default TTL.
func New(ttl time.Duration) *Memory {
	return &Memory{
		items: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}

// Get returns cached vulnerabilities for the given key.
// Returns nil, false if the key is not found or has expired.
func (c *Memory) Get(key string) ([]dependency.Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	// Return a copy to prevent external mutations.
	vulns := make([]dependency.Vulnerability, len(entry.vulns))
	copy(vulns, entry.vulns)
	return vulns, true
}

// Set stores vulnerabilities with the default TTL.
func (c *Memory) Set(key string, vulns []dependency.Vulnerability) {
	c.SetWithTTL(key, vulns, c.ttl)
}

// SetWithTTL stores vulnerabilities with a custom TTL.
func (c *Memory) SetWithTTL(key string, vulns []dependency.Vulnerability, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store a copy.
	vulnsCopy := make([]dependency.Vulnerability, len(vulns))
	copy(vulnsCopy, vulns)

	c.items[key] = &cacheEntry{
		vulns:     vulnsCopy,
		expiresAt: time.Now().Add(ttl),
	}
}

// Clear removes all entries from the cache.
func (c *Memory) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*cacheEntry)
	return nil
}

// Len returns the number of cached entries (including expired ones).
func (c *Memory) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Close is a no-op for the in-memory cache (included for interface compatibility).
func (c *Memory) Close() error {
	return nil
}
