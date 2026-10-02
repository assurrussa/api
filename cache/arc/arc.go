// Package arc provides an optional bounded-staleness ARC adapter.
package arc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	backing "github.com/assurrussa/gocache/arc"

	"github.com/assurrussa/api"
)

type key struct {
	generation uint64
	id         string
}
type cache struct {
	source   api.Source
	capacity int
	mu       sync.RWMutex
	data     *backing.Cache[key, api.ReadResult]
	cancel   context.CancelFunc
	closed   bool
}

// Factory constructs no workers. Service.Start starts the underlying cache.
func Factory(capacity int) api.CacheFactory {
	return func(source api.Source) (api.Cache, error) {
		if capacity <= 0 || source == nil || source.MaxStaleness() <= 0 {
			return nil, fmt.Errorf("%w: ARC capacity/freshness", api.ErrInvalid)
		}
		return &cache{source: source, capacity: capacity}, nil
	}
}

func (c *cache) Start(parent context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return api.ErrClosed
	}
	if c.data != nil {
		return api.ErrConflict
	}
	ctx, cancel := context.WithCancel(parent)
	data, err := backing.New[key, api.ReadResult](ctx, "api-access", c.capacity,
		backing.WithTTL(c.source.MaxStaleness()), backing.WithoutTTLJitter(), backing.WithoutPeriodicCleanup())
	if err != nil {
		cancel()
		return err
	}
	c.data, c.cancel = data, cancel
	return nil
}

func (c *cache) Lookup(ctx context.Context, id string, generation uint64) (api.ReadResult, error) {
	c.mu.RLock()
	data, closed := c.data, c.closed
	c.mu.RUnlock()
	if closed || data == nil {
		return api.ReadResult{}, api.ErrClosed
	}
	k := key{generation: generation, id: id}
	// gocache TTL starts at publication. Our original read timestamp is the
	// security deadline, so a slow load must not renew the lease.
	if entry, found := data.Get(k); found {
		if !c.source.Now().Before(entry.ReadAt.Add(c.source.MaxStaleness())) {
			data.Delete(k)
		} else if ctx.Err() == nil {
			// Preserve GetOrLoad's cancellation check without repeating its
			// backing lookup on a fresh hit. Service still fences authorization.
			return entry, nil
		}
	}
	load := func(ctx context.Context) (api.ReadResult, error) {
		return c.source.Lookup(ctx, id)
	}
	entry, err := data.GetOrLoad(ctx, k, load)
	// A follower must not inherit the canceled leader's request context.
	// The completed flight has been removed by GetOrLoad, so one retry lets a
	// live follower become the next loader without retrying arbitrary failures.
	if err != nil && ctx.Err() == nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return data.GetOrLoad(ctx, k, load)
	}
	return entry, err
}

func (c *cache) Invalidate() {
	c.mu.RLock()
	data := c.data
	c.mu.RUnlock()
	if data != nil {
		data.Purge()
	}
	// A late loader may publish into its OLD generation. That key is never
	// requested again; Service also fences its final authorization decision.
}

func (c *cache) Close() error {
	c.mu.Lock()
	c.closed = true
	cancel, data := c.cancel, c.data
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-data.Done()
	}
	return nil
}
