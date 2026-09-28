// Package rcu provides a whole-snapshot bounded-staleness cache adapter.
package rcu

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	backing "github.com/assurrussa/gocache/rcu"

	"github.com/assurrussa/api"
)

type cache struct {
	source          api.Source
	interval        time.Duration
	snapshotTimeout time.Duration
	mu              sync.RWMutex
	data            *backing.Cache[int, api.Snapshot]
	cancel          context.CancelFunc
	closed          bool
	failures        int
	nextNotify      time.Time
	wake            chan struct{}
	refreshDone     chan struct{}
	schedulerDone   chan struct{}
	scheduled       bool
}

// Factory uses the refresh interval as the snapshot load timeout for backwards
// compatibility. Use FactoryWithTimeout to configure them independently.
func Factory(refreshInterval time.Duration) api.CacheFactory {
	return FactoryWithTimeout(refreshInterval, refreshInterval)
}

// FactoryWithTimeout keeps refresh frequency, load budget, and maximum
// permissible age separate. Both durations must be positive and below
// Service's MaxStaleness.
func FactoryWithTimeout(refreshInterval, snapshotTimeout time.Duration) api.CacheFactory {
	return func(source api.Source) (api.Cache, error) {
		if source == nil || refreshInterval <= 0 || snapshotTimeout <= 0 ||
			refreshInterval >= source.MaxStaleness() || snapshotTimeout >= source.MaxStaleness() {
			return nil, fmt.Errorf("%w: RCU refresh interval and snapshot timeout must be below max staleness", api.ErrInvalid)
		}
		return &cache{
			source: source, interval: refreshInterval, snapshotTimeout: snapshotTimeout,
			wake: make(chan struct{}, 1), refreshDone: make(chan struct{}, 1),
		}, nil
	}
}

func (c *cache) Start(parent context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return api.ErrClosed
	}
	if c.data != nil {
		c.mu.Unlock()
		return api.ErrConflict
	}
	ctx, cancel := context.WithCancel(parent)
	data, err := backing.New(ctx, func(ctx context.Context) (map[int]api.Snapshot, error) {
		// The worker lifetime can be long; a single stalled query must not
		// occupy it indefinitely.
		loadCtx, stop := context.WithTimeout(ctx, c.snapshotTimeout)
		defer stop()
		snapshot, err := c.source.Snapshot(loadCtx)
		if err != nil {
			c.refreshFailed()
			c.refreshCompleted()
			return nil, err
		}
		c.mu.Lock()
		c.failures = 0
		c.mu.Unlock()
		c.refreshCompleted()
		// One published object includes metadata even for an empty snapshot.
		return map[int]api.Snapshot{0: snapshot}, nil
	}, backing.WithoutPeriodicRefresh(), backing.WithErrorHandler(func(_ context.Context, err error) {
		if reporter, ok := c.source.(interface{ ReportCacheError(err error) }); ok {
			reporter.ReportCacheError(err)
		}
	}))
	if err != nil {
		c.mu.Unlock()
		cancel()
		return err
	}
	c.data, c.cancel = data, cancel
	c.mu.Unlock()
	if err := data.WaitInitial(ctx); err != nil {
		_ = c.Close()
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return api.ErrClosed
	}
	c.schedulerDone = make(chan struct{})
	done := c.schedulerDone
	c.mu.Unlock()
	go c.schedule(ctx, data, done)
	return nil
}

func (c *cache) Lookup(ctx context.Context, id string, generation uint64) (api.ReadResult, error) {
	c.mu.RLock()
	data, closed := c.data, c.closed
	c.mu.RUnlock()
	if closed || data == nil {
		return api.ReadResult{}, api.ErrClosed
	}
	if snapshot, found := data.Get(0); found && snapshot.Generation == generation &&
		c.source.Now().Before(snapshot.ReadAt.Add(c.source.MaxStaleness())) {
		if record, ok := snapshot.Records[id]; ok {
			return api.ReadResult{Record: record, ReadAt: snapshot.ReadAt, Generation: snapshot.Generation}, nil
		}
		// Unknown attacker-controlled IDs must not trigger whole-table reloads.
		return c.source.Lookup(ctx, id)
	}
	c.requestRefresh()
	// Unknown secrets and stale/invalidated snapshots are checked at the
	// authority. A failed refresh never extends an old snapshot's lifetime.
	return c.source.Lookup(ctx, id)
}

func (c *cache) Invalidate() {
	c.requestRefresh()
}

func (c *cache) refreshFailed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures < 16 {
		c.failures++
	}
	backoff := 100 * time.Millisecond
	for i := 1; i < c.failures && backoff < c.interval; i++ {
		backoff *= 2
	}
	if backoff > c.interval {
		backoff = c.interval
	}
	// Jitter keeps many replicas from retrying a failed projection together.
	//nolint:gosec // Weak random is sufficient for backoff jitter.
	backoff = backoff*80/100 + time.Duration(rand.Int64N(int64(backoff*40/100)+1))
	c.nextNotify = time.Now().Add(backoff)
}

func (c *cache) requestRefresh() {
	c.mu.RLock()
	active := c.data != nil && !c.closed
	c.mu.RUnlock()
	if active {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

// The scheduler is the sole producer of backend notifications. A pending
// invalidation survives both an in-flight load and the throttle/backoff window.
func (c *cache) schedule(ctx context.Context, data *backing.Cache[int, api.Snapshot], done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	var pending, inFlight bool
	for {
		var timer *time.Timer
		var ready <-chan time.Time
		if pending && !inFlight {
			c.mu.RLock()
			wait := time.Until(c.nextNotify)
			c.mu.RUnlock()
			if wait <= 0 {
				if ctx.Err() != nil {
					return
				}
				c.mu.Lock()
				c.scheduled = true
				c.nextNotify = time.Now().Add(min(100*time.Millisecond, c.interval))
				c.mu.Unlock()
				data.Notify()
				pending, inFlight = false, true
				continue
			}
			timer = time.NewTimer(wait)
			ready = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-c.wake:
			pending = true
		case <-ticker.C:
			pending = true
		case <-c.refreshDone:
			inFlight = false
		case <-ready:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *cache) refreshCompleted() {
	c.mu.Lock()
	scheduled := c.scheduled
	c.scheduled = false
	c.mu.Unlock()
	if scheduled {
		c.refreshDone <- struct{}{}
	}
}

func (c *cache) Close() error {
	c.mu.Lock()
	c.closed = true
	cancel, data, done := c.cancel, c.data, c.schedulerDone
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-data.Done()
	}
	if done != nil {
		<-done
	}
	return nil
}
