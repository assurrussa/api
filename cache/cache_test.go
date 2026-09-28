package cache_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
)

type source struct {
	mu            sync.Mutex
	now           time.Time
	generation    uint64
	banned        bool
	err           error
	lookupHook    func()
	snapshotHook  func()
	lookupFn      func(context.Context) (api.ReadResult, error)
	snapshotFn    func(context.Context) (api.Snapshot, error)
	snapshotCalls int
	reported      chan error
}

func (s *source) Now() time.Time            { s.mu.Lock(); defer s.mu.Unlock(); return s.now }
func (*source) MaxStaleness() time.Duration { return time.Minute }
func (s *source) read() (res api.ReadResult, lookupHook func(), snapshotHook func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res = api.ReadResult{
		ReadAt:     s.now,
		Generation: s.generation,
		Record:     api.Record{Client: api.Client{Banned: s.banned}},
	}
	return res, s.lookupHook, s.snapshotHook, s.err
}

func (s *source) Lookup(ctx context.Context, _ string) (api.ReadResult, error) {
	s.mu.Lock()
	fn := s.lookupFn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	r, hook, _, err := s.read()
	if hook != nil {
		hook()
	}
	return r, err
}

func (s *source) Snapshot(ctx context.Context) (api.Snapshot, error) {
	s.mu.Lock()
	s.snapshotCalls++
	fn := s.snapshotFn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	r, _, hook, err := s.read()
	if hook != nil {
		hook()
	}
	if err != nil {
		return api.Snapshot{}, err
	}
	return api.Snapshot{ReadAt: r.ReadAt, Generation: r.Generation, Records: map[string]api.Record{"key": r.Record}}, nil
}

func (s *source) ReportCacheError(err error) {
	if s.reported != nil {
		select {
		case s.reported <- err:
		default:
		}
	}
}

func TestARCWaiterRetriesCanceledLeader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &source{now: time.Now()}
		entered := make(chan struct{})
		var calls atomic.Int32
		s.lookupFn = func(ctx context.Context) (api.ReadResult, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-ctx.Done()
				return api.ReadResult{}, ctx.Err()
			}
			r, _, _, _ := s.read()
			return r, nil
		}
		c, err := arc.Factory(4)(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		leaderCtx, cancel := context.WithCancel(context.Background())
		leader := make(chan error, 1)
		go func() { _, err := c.Lookup(leaderCtx, "key", 0); leader <- err }()
		<-entered
		follower := make(chan error, 1)
		go func() { _, err := c.Lookup(context.Background(), "key", 0); follower <- err }()
		// Both lookups are now durably blocked on the first load. The follower
		// has joined the flight, rather than racing with leader cancellation.
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("loads before cancellation=%d, want one shared flight", got)
		}
		cancel()
		if err := <-leader; !errors.Is(err, context.Canceled) {
			t.Fatalf("leader: %v", err)
		}
		if err := <-follower; err != nil {
			t.Fatalf("follower inherited cancellation: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("loads=%d, want canceled and retried", calls.Load())
		}
	})
}

func TestRCUFailedRefreshThrottlesSequentialRequests(t *testing.T) {
	s := &source{now: time.Now(), reported: make(chan error, 1)}
	c, err := rcu.Factory(time.Second)(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.mu.Lock()
	s.err = errors.New("snapshot offline")
	s.generation = 1
	s.mu.Unlock()
	c.Invalidate()
	deadline := time.After(time.Second)
	for {
		s.mu.Lock()
		calls := s.snapshotCalls
		s.mu.Unlock()
		if calls >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("refresh did not run")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-s.reported:
	case <-time.After(time.Second):
		t.Fatal("refresh failure was not reported")
	}
	for range 20 {
		if _, err := c.Lookup(context.Background(), "key", 1); err == nil {
			t.Fatal("fallback unexpectedly succeeded")
		}
	}
	s.mu.Lock()
	calls := s.snapshotCalls
	s.mu.Unlock()
	if calls > 3 {
		t.Fatalf("sequential requests caused %d snapshots", calls)
	}
}

func TestRCUSnapshotTimeoutAllowsRecovery(t *testing.T) {
	s := &source{now: time.Now(), reported: make(chan error, 2)}
	c, err := rcu.Factory(50 * time.Millisecond)(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.mu.Lock()
	s.snapshotFn = func(ctx context.Context) (api.Snapshot, error) { <-ctx.Done(); return api.Snapshot{}, ctx.Err() }
	s.mu.Unlock()
	c.Invalidate()
	select {
	case err := <-s.reported:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("snapshot error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled snapshot was not timed out")
	}
	s.mu.Lock()
	s.snapshotFn = nil
	s.generation = 1
	var pointReads atomic.Int32
	s.lookupFn = func(context.Context) (api.ReadResult, error) {
		pointReads.Add(1)
		return api.ReadResult{}, errors.New("point lookup unavailable")
	}
	s.mu.Unlock()
	deadline := time.After(time.Second)
	for {
		before := pointReads.Load()
		if r, err := c.Lookup(context.Background(), "key", 1); err == nil && r.Generation == 1 {
			if after := pointReads.Load(); after != before {
				t.Fatalf("recovered lookup used authority: before=%d after=%d", before, after)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("snapshot did not recover after timeout")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestAdaptersExpireFromReadTime(t *testing.T) {
	for name, factory := range map[string]api.CacheFactory{"arc": arc.Factory(4), "rcu": rcu.Factory(30 * time.Second)} {
		t.Run(name, func(t *testing.T) {
			s := &source{now: time.Now()}
			c, err := factory(s)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			if _, err := c.Lookup(context.Background(), "key", 0); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.now = s.now.Add(time.Minute)
			s.err = errors.New("offline")
			s.mu.Unlock()
			if _, err := c.Lookup(context.Background(), "key", 0); err == nil {
				t.Fatal("stale cache bypassed authority failure")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Lookup(context.Background(), "key", 0); !errors.Is(err, api.ErrClosed) {
				t.Fatalf("after Close: %v", err)
			}
		})
	}
}

func TestARCLateLoaderUsesUnreachableGeneration(t *testing.T) {
	s := &source{now: time.Now()}
	c, err := arc.Factory(4)(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.mu.Lock()
	s.lookupHook = func() { once.Do(func() { close(entered); <-release }) }
	s.mu.Unlock()
	old := make(chan api.ReadResult, 1)
	go func() { r, _ := c.Lookup(context.Background(), "key", 0); old <- r }()
	<-entered
	s.mu.Lock()
	s.generation = 1
	s.banned = true
	s.lookupHook = nil
	s.mu.Unlock()
	c.Invalidate()
	current, err := c.Lookup(context.Background(), "key", 1)
	if err != nil || !current.Record.Client.Banned {
		t.Fatalf("new generation: %+v %v", current, err)
	}
	close(release)
	<-old
	current, err = c.Lookup(context.Background(), "key", 1)
	if err != nil || !current.Record.Client.Banned {
		t.Fatalf("late load resurrected cache: %+v %v", current, err)
	}
}

func TestRCURejectsLateSnapshotGeneration(t *testing.T) {
	s := &source{now: time.Now()}
	c, err := rcu.Factory(30 * time.Second)(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.mu.Lock()
	s.snapshotHook = func() { once.Do(func() { close(entered); <-release }) }
	s.mu.Unlock()
	c.Invalidate()
	<-entered
	s.mu.Lock()
	s.generation = 1
	s.banned = true
	s.snapshotHook = nil
	s.mu.Unlock()
	c.Invalidate()
	close(release)
	for range 5 {
		r, err := c.Lookup(context.Background(), "key", 1)
		if err != nil || !r.Record.Client.Banned || r.Generation != 1 {
			t.Fatalf("stale snapshot accepted: %+v %v", r, err)
		}
	}
}

func TestRCUInitialFailure(t *testing.T) {
	s := &source{now: time.Now(), err: errors.New("partial snapshot")}
	c, err := rcu.Factory(30 * time.Second)(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("partial snapshot accepted")
	}
	_ = c.Close()
}
