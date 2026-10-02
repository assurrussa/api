package cache_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
)

type sourceWithNowHook struct {
	api.Source
	onNow func()
}

func (s sourceWithNowHook) Now() time.Time {
	at := s.Source.Now()
	s.onNow()
	return at
}

func TestARCWarmHitPreservesCancellation(t *testing.T) {
	for _, duringRead := range []bool{false, true} {
		name := "before lookup"
		if duringRead {
			name = "during freshness check"
		}
		t.Run(name, func(t *testing.T) {
			checkARCWarmHitCancellation(t, duringRead)
		})
	}
}

func checkARCWarmHitCancellation(t *testing.T, duringRead bool) {
	t.Helper()
	s := &source{now: time.Now()}
	var reads, nowCalls atomic.Int32
	s.lookupFn = func(context.Context) (api.ReadResult, error) {
		reads.Add(1)
		r, _, _, err := s.read()
		return r, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := sourceWithNowHook{Source: s, onNow: func() {
		nowCalls.Add(1)
		if duringRead {
			cancel()
		}
	}}
	c, err := arc.Factory(4)(wrapped)
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
	if !duringRead {
		cancel()
	}
	if _, err := c.Lookup(ctx, "key", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("warm lookup cancellation: %v", err)
	}
	if nowCalls.Load() != 1 {
		t.Fatal("test did not exercise the warm freshness check")
	}
	if _, err := c.Lookup(context.Background(), "key", 0); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 {
		t.Fatalf("canceled lookup discarded fresh entry: reads=%d", reads.Load())
	}
}
