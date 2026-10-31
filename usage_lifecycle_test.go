package api_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/assurrussa/api"
)

type controlledUsageCall struct {
	ctx      context.Context //nolint:containedctx // Captured only to assert cancellation and flush context independence.
	batch    []api.UsageObservation
	reply    chan error
	returned chan struct{}
}
type controlledUsageStore struct {
	*testStore
	calls   chan controlledUsageCall
	release chan struct{}
}

func (st *controlledUsageStore) RecordUsage(ctx context.Context, batch []api.UsageObservation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call := controlledUsageCall{ctx: ctx, batch: slices.Clone(batch), reply: make(chan error, 1), returned: make(chan struct{})}
	defer close(call.returned)
	select {
	case <-st.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case st.calls <- call:
	}
	select {
	case <-st.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case err := <-call.reply:
		return err
	}
}

type usageHarness struct {
	service *api.Service
	store   *controlledUsageStore
	token   string
	now     time.Time
	elapsed atomic.Int64
}

func newUsageHarness(t *testing.T, cfg api.UsageConfig) *usageHarness {
	t.Helper()
	_, base, token, _ := fixture(t)
	h := &usageHarness{
		store: &controlledUsageStore{testStore: base, calls: make(chan controlledUsageCall, 16), release: make(chan struct{})},
		token: token, now: base.record.Secret.ExpiresAt.Add(-time.Hour),
	}
	var err error
	h.service, err = api.New(h.store, api.Config{
		Scopes: []string{testScopeRead, testScopeWrite}, DefaultTTL: time.Hour, MaxTTL: time.Hour,
	}, api.WithUsageTracking(cfg), api.WithClock(func() time.Time { return h.now.Add(time.Duration(h.elapsed.Load())) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(h.store.release); _ = h.service.Close() })
	return h
}

func awaitUsageCall(t *testing.T, h *usageHarness) controlledUsageCall {
	t.Helper()
	select {
	case call := <-h.store.calls:
		return call
	case <-time.After(3 * time.Second):
		t.Fatal("usage write did not start")
		return controlledUsageCall{}
	}
}

func awaitUsageSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("usage operation did not finish")
	}
}

func awaitUsageClose(t *testing.T, closed <-chan error) error {
	t.Helper()
	select {
	case err := <-closed:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not finish")
		return nil
	}
}

func useTrackedKey(t *testing.T, ctx context.Context, h *usageHarness) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := h.service.Authenticate(ctx, h.token, testScopeRead); err != nil {
		t.Fatal(err)
	}
}

func startUsageHarness(t *testing.T, ctx context.Context, h *usageHarness) {
	t.Helper()
	useTrackedKey(t, ctx, h)
	if err := h.service.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

func requireUsageTime(t *testing.T, call controlledUsageCall, want time.Time) {
	t.Helper()
	if len(call.batch) != 1 || !call.batch[0].At.Equal(want) {
		t.Fatalf("usage batch=%+v, want %s", call.batch, want)
	}
}

func TestUsageUpdateDuringBlockedFlushIsPreserved(t *testing.T) {
	h := newUsageHarness(t, api.UsageConfig{FlushInterval: time.Millisecond, FlushTimeout: time.Second})
	startUsageHarness(t, t.Context(), h)
	first := awaitUsageCall(t, h)
	requireUsageTime(t, first, h.now)
	h.elapsed.Store(int64(time.Minute))
	// Authentication must finish while RecordUsage is blocked, and the new mark
	// must survive acknowledgement of the earlier batch.
	useTrackedKey(t, t.Context(), h)
	first.reply <- nil
	awaitUsageSignal(t, first.returned)
	second := awaitUsageCall(t, h)
	requireUsageTime(t, second, h.now.Add(time.Minute))
	second.reply <- nil
	awaitUsageSignal(t, second.returned)
	if err := h.service.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := h.service.UsageStats(); stats.Pending != 0 || stats.Dropped != 0 {
		t.Fatal(stats)
	}
}

func TestUsageCloseCancelsBlockedWorkerAndFlushesLatestMark(t *testing.T) {
	h := newUsageHarness(t, api.UsageConfig{FlushInterval: time.Millisecond, FlushTimeout: time.Second, CloseTimeout: time.Second})
	startUsageHarness(t, t.Context(), h)
	blocked := awaitUsageCall(t, h)
	h.elapsed.Store(int64(time.Minute))
	useTrackedKey(t, t.Context(), h)
	closed := make(chan error, 1)
	go func() { closed <- h.service.Close() }()
	awaitUsageSignal(t, blocked.returned)
	if !errors.Is(blocked.ctx.Err(), context.Canceled) {
		t.Fatalf("worker context: %v", blocked.ctx.Err())
	}
	final := awaitUsageCall(t, h)
	if err := final.ctx.Err(); err != nil {
		t.Fatalf("final flush inherited cancellation: %v", err)
	}
	requireUsageTime(t, final, h.now.Add(time.Minute))
	if _, err := h.service.Authenticate(context.Background(), h.token); !errors.Is(err, api.ErrClosed) {
		t.Fatal(err)
	}
	// Concurrent Close waits for the same final write, rather than starting another.
	again := make(chan error, 1)
	entered := make(chan struct{})
	go func() { close(entered); again <- h.service.Close() }()
	awaitUsageSignal(t, entered)
	select {
	case err := <-closed:
		t.Fatalf("first Close returned before final write: %v", err)
	case err := <-again:
		t.Fatalf("concurrent Close returned before final write: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	final.reply <- nil
	if err := awaitUsageClose(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := awaitUsageClose(t, again); err != nil {
		t.Fatal(err)
	}
	if stats := h.service.UsageStats(); stats.Pending != 0 {
		t.Fatal(stats)
	}
	select {
	case <-h.store.calls:
		t.Fatal("duplicate final usage write")
	default:
	}
}

func TestUsageParentCancellationStopsWorkerButCloseDrains(t *testing.T) {
	h := newUsageHarness(t, api.UsageConfig{FlushInterval: time.Millisecond, FlushTimeout: time.Second, CloseTimeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startUsageHarness(t, ctx, h)
	blocked := awaitUsageCall(t, h)
	cancel()
	awaitUsageSignal(t, blocked.returned)
	if !errors.Is(blocked.ctx.Err(), context.Canceled) {
		t.Fatal(blocked.ctx.Err())
	}
	if _, err := h.service.Authenticate(context.Background(), h.token); !errors.Is(err, api.ErrClosed) {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- h.service.Close() }()
	final := awaitUsageCall(t, h)
	requireUsageTime(t, final, h.now)
	if err := final.ctx.Err(); err != nil {
		t.Fatal(err)
	}
	final.reply <- nil
	if err := awaitUsageClose(t, closed); err != nil {
		t.Fatal(err)
	}
}

func TestUsageFlushTimeoutRetainsAndRetriesWithoutDenying(t *testing.T) {
	h := newUsageHarness(t, api.UsageConfig{FlushInterval: time.Millisecond, FlushTimeout: 100 * time.Millisecond})
	startUsageHarness(t, t.Context(), h)
	first := awaitUsageCall(t, h)
	useTrackedKey(t, t.Context(), h)
	awaitUsageSignal(t, first.returned)
	if !errors.Is(first.ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(first.ctx.Err())
	}
	select {
	case err := <-h.service.Errors():
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flush failure not observable")
	}
	if h.service.UsageStats().Pending != 1 {
		t.Fatal(h.service.UsageStats())
	}
	retry := awaitUsageCall(t, h)
	requireUsageTime(t, retry, h.now)
	retry.reply <- nil
	awaitUsageSignal(t, retry.returned)
	if err := h.service.Close(); err != nil {
		t.Fatal(err)
	}
	if h.service.UsageStats().Pending != 0 {
		t.Fatal(h.service.UsageStats())
	}
}

func TestUsageCloseTimeoutReturnsErrorAndRetainsPending(t *testing.T) {
	h := newUsageHarness(t, api.UsageConfig{CloseTimeout: 20 * time.Millisecond})
	useTrackedKey(t, t.Context(), h)
	closed := make(chan error, 1)
	go func() { closed <- h.service.Close() }()
	final := awaitUsageCall(t, h)
	awaitUsageSignal(t, final.returned)
	if err := awaitUsageClose(t, closed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if stats := h.service.UsageStats(); stats.Pending != 1 || !stats.LastFlushAt.IsZero() {
		t.Fatal(stats)
	}
}

func TestUsageRejectsInvalidExpiredRevokedAndBannedSecrets(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*usageHarness)
	}{
		{name: "expired", mutate: func(h *usageHarness) { h.elapsed.Store(int64(2 * time.Hour)) }},
		{name: "revoked", mutate: func(h *usageHarness) { at := h.now; h.store.record.Credential.RevokedAt = &at }},
		{name: "banned", mutate: func(h *usageHarness) { h.store.record.Client.Banned = true }},
		{name: "wrong secret", mutate: func(h *usageHarness) { h.store.record.Secret.Digest = [32]byte{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUsageHarness(t, api.UsageConfig{})
			tc.mutate(h)
			if _, err := h.service.Authenticate(context.Background(), h.token); !errors.Is(err, api.ErrUnauthorized) {
				t.Fatal(err)
			}
			if h.service.UsageStats().Pending != 0 {
				t.Fatal(h.service.UsageStats())
			}
			if err := h.service.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-h.store.calls:
				t.Fatal("invalid key recorded as usage")
			default:
			}
		})
	}
}

func TestUsageOptionCanBeSharedByConcurrentConstructors(t *testing.T) {
	option := api.WithUsageTracking(api.UsageConfig{})
	h := newUsageHarness(t, api.UsageConfig{})
	store := h.store
	ready := make(chan struct{})
	errs := make(chan error, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			<-ready
			service, err := api.New(store, api.Config{DefaultTTL: time.Hour, MaxTTL: time.Hour}, option)
			if err == nil {
				err = service.Close()
			}
			errs <- err
		})
	}
	close(ready)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUsageFinalFlushWaitsForAdmittedAuthentication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newUsageHarness(t, api.UsageConfig{})
		useTrackedKey(t, t.Context(), h)
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		// A second request has entered Service.begin but cannot finish its source
		// lookup yet. It deliberately releases only after shutdown starts.
		h.store.mu.Lock()
		h.store.hook = func(_ context.Context, r api.Record) (api.Record, error) { close(entered); <-release; return r, nil }
		h.store.mu.Unlock()
		authenticated := make(chan error, 1)
		go func() { _, err := h.service.Authenticate(t.Context(), h.token); authenticated <- err }()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- h.service.Close() }()
		// Wait proves Close has reached its wait, rather than merely relying on the
		// scheduling of goroutines. No network or wall-clock sleeps enter this bubble.
		synctest.Wait()
		select {
		case <-h.store.calls:
			t.Fatal("final usage write preceded an admitted request's completion")
		default:
		}
		select {
		case err := <-closed:
			t.Fatalf("Close ignored admitted request: %v", err)
		default:
		}
		unblock()
		synctest.Wait()
		if err := <-authenticated; !errors.Is(err, api.ErrClosed) {
			t.Fatal(err)
		}
		select {
		case final := <-h.store.calls:
			requireUsageTime(t, final, h.now)
			final.reply <- nil
		default:
			t.Fatal("Close failed to drain usage after request completion")
		}
		synctest.Wait()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	})
}
