package api

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// WithUsageTracking enables bounded, best-effort LastUsedAt collection. Zero
// fields use defaults; failure to persist statistics never denies access.
func WithUsageTracking(cfg UsageConfig) Option {
	return func(s *settings) error {
		resolved := cfg
		if resolved.FlushInterval == 0 {
			resolved.FlushInterval = 30 * time.Second
		}
		if resolved.FlushTimeout == 0 {
			resolved.FlushTimeout = 5 * time.Second
		}
		if resolved.CloseTimeout == 0 {
			resolved.CloseTimeout = 5 * time.Second
		}
		if resolved.BatchSize == 0 {
			resolved.BatchSize = 1000
		}
		if resolved.MaxPending == 0 {
			resolved.MaxPending = 10000
		}
		if resolved.FlushInterval < 0 || resolved.FlushTimeout < 0 || resolved.CloseTimeout < 0 || resolved.BatchSize < 1 ||
			resolved.BatchSize > 1000 || resolved.MaxPending < 1 {
			return fmt.Errorf("%w: usage configuration", ErrInvalid)
		}
		s.usage = &resolved
		return nil
	}
}

type usageTracker struct {
	store   UsageStore
	cfg     UsageConfig
	mu      sync.Mutex
	pending map[string]UsageObservation
	stats   UsageStats
}

func newUsageTracker(store UsageStore, cfg UsageConfig) *usageTracker {
	return &usageTracker{store: store, cfg: cfg, pending: make(map[string]UsageObservation)}
}

func (u *usageTracker) observe(o UsageObservation) {
	u.mu.Lock()
	defer u.mu.Unlock()
	previous, exists := u.pending[o.VersionID]
	if !exists && len(u.pending) >= u.cfg.MaxPending {
		u.stats.Dropped++
		return
	}
	if !exists || previous.At.Before(o.At) {
		u.pending[o.VersionID] = o
	}
}

func (u *usageTracker) batch() []UsageObservation {
	u.mu.Lock()
	defer u.mu.Unlock()
	batch := make([]UsageObservation, 0, min(u.cfg.BatchSize, len(u.pending)))
	for _, o := range u.pending {
		batch = append(batch, o)
		if len(batch) == u.cfg.BatchSize {
			break
		}
	}
	return batch
}

func (u *usageTracker) flush(ctx context.Context) error {
	// Snapshot the initial size: a busy integration cannot prevent this flush
	// from completing by continuously adding new observations.
	u.mu.Lock()
	remaining := len(u.pending)
	u.mu.Unlock()
	for remaining > 0 {
		batch := u.batch()
		if len(batch) == 0 {
			return nil
		}
		if err := u.store.RecordUsage(ctx, batch); err != nil {
			return err
		}
		u.mu.Lock()
		for _, o := range batch {
			if current, ok := u.pending[o.VersionID]; ok && !current.At.After(o.At) {
				delete(u.pending, o.VersionID)
			}
		}
		u.stats.LastFlushAt = time.Now().UTC()
		u.mu.Unlock()
		remaining -= len(batch)
	}
	return nil
}

func (s *Service) startUsage(ctx context.Context) {
	u := s.usage
	u.mu.Lock()
	u.stats.Started = true
	u.mu.Unlock()
	s.workers.Go(func() {
		ticker := time.NewTicker(u.cfg.FlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(ctx, u.cfg.FlushTimeout)
				err := u.flush(ctx)
				cancel()
				if err != nil {
					s.report("usage", err)
				}
			}
		}
	})
}

func (u *usageTracker) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), u.cfg.CloseTimeout)
	defer cancel()
	return u.flush(ctx)
}

// UsageStats reports local collection state. Missing observations never prove
// that a key is unused; other replicas and dropped observations are not included.
func (s *Service) UsageStats() UsageStats {
	if s.usage == nil {
		return UsageStats{}
	}
	s.usage.mu.Lock()
	defer s.usage.mu.Unlock()
	stats := s.usage.stats
	stats.Pending = len(s.usage.pending)
	return stats
}
