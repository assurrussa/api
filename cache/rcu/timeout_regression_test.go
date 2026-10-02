package rcu_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/rcu"
)

func TestStartRejectsSnapshotReturnedAfterDeadline(t *testing.T) {
	s := &schedulerSource{reported: make(chan error, 1)}
	s.load = func(ctx context.Context, _ int32) (api.Snapshot, error) {
		<-ctx.Done()
		return s.snapshot(), nil
	}
	c, err := rcu.FactoryWithTimeout(5*time.Second, 20*time.Millisecond)(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Start(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start accepted Snapshot after its deadline: err=%v, want DeadlineExceeded", err)
	}
}

func TestLateSnapshotRetainsPublicationAndBackoff(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &schedulerSource{reported: make(chan error, 2)}
	entered := make(chan struct{})
	third := make(chan time.Time, 1)
	releaseThird := make(chan struct{})
	s.load = func(ctx context.Context, n int32) (api.Snapshot, error) {
		switch n {
		case 2:
			close(entered)
			<-ctx.Done()
			return s.snapshot(), nil
		case 3:
			third <- time.Now()
			select {
			case <-releaseThird:
			case <-parent.Done():
				return api.Snapshot{}, parent.Err()
			}
		}
		return s.snapshot(), nil
	}
	v, err := rcu.FactoryWithTimeout(5*time.Second, 100*time.Millisecond)(s)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := v.(*rcu.Cache)
	if !ok {
		t.Fatal("expected *rcu.Cache")
	}
	defer func() {
		cancel()
		_ = c.Close()
	}()
	if err := c.Start(parent); err != nil {
		t.Fatal(err)
	}
	before, ok := c.PublishedSnapshot()
	if !ok {
		t.Fatal("initial snapshot missing")
	}
	s.generation.Store(1)
	c.Invalidate()
	waitSignal(t, entered)
	c.Invalidate()
	select {
	case err := <-s.reported:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("late Snapshot error=%v, want DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		after, _ := c.PublishedSnapshot()
		t.Fatalf("late Snapshot was accepted: generation=%d; timeout failure was not reported", after.Generation)
	}
	deadline := c.NextNotify()
	after, ok := c.PublishedSnapshot()
	if !ok || !after.ReadAt.Equal(before.ReadAt) || after.Generation != before.Generation {
		t.Fatalf("late refresh changed publication: before=%+v after=%+v", before, after)
	}
	select {
	case started := <-third:
		if started.Before(deadline) {
			t.Fatalf("retry started %v before failure backoff deadline %v", started, deadline)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued invalidation was lost after deadline failure")
	}
	close(releaseThird)
	waitGeneration(t, c, 1)
}
