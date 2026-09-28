package rcu

import (
	"time"

	"github.com/assurrussa/api"
)

// Cache is exported for testing in rcu_test.
type Cache = cache

// NextNotify returns the next scheduled notification time.
func (c *cache) NextNotify() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nextNotify
}

// PublishedSnapshot returns the snapshot currently stored in the cache.
func (c *cache) PublishedSnapshot() (api.Snapshot, bool) {
	if c.data == nil {
		return api.Snapshot{}, false
	}
	return c.data.Get(0)
}
