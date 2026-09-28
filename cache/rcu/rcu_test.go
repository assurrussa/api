package rcu_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/rcu"
)

type schedulerSource struct {
	generation atomic.Uint64
	lookups    atomic.Int32
	calls      atomic.Int32
	load       func(context.Context, int32) (api.Snapshot, error)
	reported   chan error
}

func (s *schedulerSource) Now() time.Time              { return time.Now() }
func (s *schedulerSource) MaxStaleness() time.Duration { return time.Minute }

func (s *schedulerSource) snapshot() api.Snapshot {
	return api.Snapshot{
		ReadAt:     time.Now(),
		Generation: s.generation.Load(),
		Records:    map[string]api.Record{"key": {Client: api.Client{ID: "client"}}},
	}
}

func (s *schedulerSource) Snapshot(ctx context.Context) (api.Snapshot, error) {
	n := s.calls.Add(1)
	if s.load != nil {
		return s.load(ctx, n)
	}
	return s.snapshot(), nil
}

func (s *schedulerSource) Lookup(ctx context.Context, id string) (api.ReadResult, error) {
	s.lookups.Add(1)
	if err := ctx.Err(); err != nil {
		return api.ReadResult{}, err
	}
	v := s.snapshot()
	return api.ReadResult{Record: v.Records[id], ReadAt: v.ReadAt, Generation: v.Generation}, nil
}

func (s *schedulerSource) ReportCacheError(err error) {
	select {
	case s.reported <- err:
	default:
	}
}

func startSchedulerCache(t *testing.T, s *schedulerSource, interval time.Duration) *rcu.Cache {
	t.Helper()
	v, err := rcu.Factory(interval)(s)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := v.(*rcu.Cache)
	if !ok {
		t.Fatal("expected *rcu.Cache")
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for refresh")
	}
}

func waitGeneration(t *testing.T, c *rcu.Cache, generation uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := c.PublishedSnapshot(); ok && v.Generation == generation {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("generation %d was not published", generation)
}

func TestQueuedInvalidationWaitsForFailureBackoff(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 4)}
	entered := make(chan struct{})
	release := make(chan struct{})
	third := make(chan time.Time, 1)
	s.load = func(ctx context.Context, n int32) (api.Snapshot, error) {
		switch n {
		case 1:
			return s.snapshot(), nil
		case 2:
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return api.Snapshot{}, ctx.Err()
			}
			return api.Snapshot{}, errors.New("projection offline")
		case 3:
			third <- time.Now()
		}
		return s.snapshot(), nil
	}
	c := startSchedulerCache(t, s, 5*time.Second)
	c.Invalidate()
	waitSignal(t, entered)
	// Queue the second invalidation while the first refresh still owns the loader.
	c.Invalidate()
	close(release)
	select {
	case <-s.reported:
	case <-time.After(time.Second):
		t.Fatal("refresh error was not reported")
	}
	deadline := c.NextNotify()
	select {
	case started := <-third:
		if started.Before(deadline) {
			t.Fatalf("queued Snapshot started %v before backoff deadline %v", started, deadline)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued refresh was lost")
	}
}

func TestPeriodicTickWaitsForFailureBackoff(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 4)}
	third := make(chan time.Time, 1)
	s.load = func(_ context.Context, n int32) (api.Snapshot, error) {
		if n == 2 {
			return api.Snapshot{}, errors.New("projection offline")
		}
		if n == 3 {
			third <- time.Now()
		}
		return s.snapshot(), nil
	}
	c := startSchedulerCache(t, s, 40*time.Millisecond)
	c.Invalidate()
	select {
	case <-s.reported:
	case <-time.After(time.Second):
		t.Fatal("refresh error was not reported")
	}
	deadline := c.NextNotify()
	select {
	case started := <-third:
		if started.Before(deadline) {
			t.Fatalf("periodic Snapshot started %v before backoff deadline %v", started, deadline)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("periodic refresh was lost")
	}
}

func TestInvalidationDuringThrottleIsDeferred(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 4)}
	entered := make(chan struct{})
	release := make(chan struct{})
	s.load = func(ctx context.Context, n int32) (api.Snapshot, error) {
		v := s.snapshot()
		if n == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return api.Snapshot{}, ctx.Err()
			}
		}
		return v, nil
	}
	c := startSchedulerCache(t, s, 5*time.Second)
	s.generation.Store(1)
	c.Invalidate()
	waitSignal(t, entered)
	s.generation.Store(2)
	c.Invalidate()
	close(release)
	waitGeneration(t, c, 2)
	if got := s.calls.Load(); got != 3 {
		t.Fatalf("Snapshot calls=%d, want initial and two refreshes", got)
	}
	if _, err := c.Lookup(context.Background(), "key", 2); err != nil {
		t.Fatal(err)
	}
	if got := s.lookups.Load(); got != 0 {
		t.Fatalf("published snapshot fell back to source.Lookup %d times", got)
	}
}

func TestTimeoutRecoveryPublishesCacheHit(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 4)}
	var blocked atomic.Bool
	s.load = func(ctx context.Context, _ int32) (api.Snapshot, error) {
		if blocked.Load() {
			<-ctx.Done()
			return api.Snapshot{}, ctx.Err()
		}
		return s.snapshot(), nil
	}
	c := startSchedulerCache(t, s, 50*time.Millisecond)
	blocked.Store(true)
	c.Invalidate()
	select {
	case err := <-s.reported:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot did not time out")
	}
	s.generation.Store(1)
	blocked.Store(false)
	waitGeneration(t, c, 1)
	if _, err := c.Lookup(context.Background(), "key", 1); err != nil {
		t.Fatal(err)
	}
	if got := s.lookups.Load(); got != 0 {
		t.Fatalf("recovery used source.Lookup %d times", got)
	}
}

func TestFailedRefreshKeepsReadAtAndFallsBackForNewGeneration(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 4)}
	s.load = func(_ context.Context, n int32) (api.Snapshot, error) {
		if n > 1 {
			return api.Snapshot{}, errors.New("projection offline")
		}
		return s.snapshot(), nil
	}
	c := startSchedulerCache(t, s, 5*time.Second)
	before, ok := c.PublishedSnapshot()
	if !ok {
		t.Fatal("initial snapshot missing")
	}
	s.generation.Store(1)
	c.Invalidate()
	select {
	case <-s.reported:
	case <-time.After(time.Second):
		t.Fatal("refresh error was not reported")
	}
	after, ok := c.PublishedSnapshot()
	if !ok || !after.ReadAt.Equal(before.ReadAt) || after.Generation != before.Generation {
		t.Fatalf("failed refresh changed published snapshot: before=%+v after=%+v", before, after)
	}
	result, err := c.Lookup(context.Background(), "key", 1)
	if err != nil || result.Generation != 1 || s.lookups.Load() != 1 {
		t.Fatalf("new generation did not reach source: result=%+v err=%v lookups=%d", result, err, s.lookups.Load())
	}
}

func TestSnapshotTimeoutIsIndependentOfRefreshInterval(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 1)}
	s.load = func(ctx context.Context, _ int32) (api.Snapshot, error) {
		select {
		case <-time.After(150 * time.Millisecond):
			return s.snapshot(), nil
		case <-ctx.Done():
			return api.Snapshot{}, ctx.Err()
		}
	}
	v, err := rcu.FactoryWithTimeout(50*time.Millisecond, 300*time.Millisecond)(s)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := v.(*rcu.Cache)
	if !ok {
		t.Fatal("expected *rcu.Cache")
	}
	defer c.Close()
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("slow initial snapshot should fit its independent timeout: %v", err)
	}
	if got := s.calls.Load(); got != 1 {
		t.Fatalf("initial Snapshot calls=%d, want 1", got)
	}
	if _, err := rcu.FactoryWithTimeout(50*time.Millisecond, time.Minute)(s); !errors.Is(err, api.ErrInvalid) {
		t.Fatalf("timeout at MaxStaleness: %v, want ErrInvalid", err)
	}
}
