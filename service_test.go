package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assurrussa/api"
)

const testClientID = "client"

type testStore struct {
	api.Store
	mu       sync.Mutex
	record   api.Record
	err      error
	writeErr error
	reads    int
	hook     func(context.Context, api.Record) (api.Record, error)
}

func (st *testStore) Lookup(ctx context.Context, id string) (api.Record, error) {
	st.mu.Lock()
	st.reads++
	record, err, hook := api.CloneRecord(st.record), st.err, st.hook
	st.mu.Unlock()
	if err != nil {
		return api.Record{}, err
	}
	if hook != nil {
		return hook(ctx, record)
	}
	if id != record.Secret.ID {
		return api.Record{}, api.ErrNotFound
	}
	return record, nil
}

func (st *testStore) Snapshot(context.Context) (map[string]api.Record, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.err != nil {
		return nil, st.err
	}
	return map[string]api.Record{st.record.Secret.ID: api.CloneRecord(st.record)}, nil
}

func (st *testStore) SetClientBanned(_ context.Context, id string, banned bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if id == st.record.Client.ID {
		st.record.Client.Banned = banned
	}
	return st.writeErr
}

func (st *testStore) Revoke(_ context.Context, _ string, at time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.record.Credential.RevokedAt = &at
	return nil
}

func (st *testStore) SetClientScopes(_ context.Context, _ string, scopes []string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.record.Client.Scopes = append([]string(nil), scopes...)
	return nil
}

type heldCache struct {
	source api.Source
	mu     sync.Mutex
	value  api.ReadResult
	loaded bool
}

func (c *heldCache) Start(context.Context) error { return nil }

func (c *heldCache) Close() error { return nil }

func (c *heldCache) Invalidate() {} // Deliberately retain old data to exercise the core fence.

func (c *heldCache) Lookup(ctx context.Context, key string, _ uint64) (api.ReadResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return c.value, nil
	}
	v, err := c.source.Lookup(ctx, key)
	if err == nil {
		c.value, c.loaded = v, true
	}
	return v, err
}

func heldFactory(source api.Source) (api.Cache, error) { return &heldCache{source: source}, nil }

func fixture(t *testing.T, options ...api.Option) (*api.Service, *testStore, string, func(time.Duration)) {
	t.Helper()
	base := time.Now()
	var elapsed atomic.Int64
	clock := func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
	options = append(options, api.WithClock(clock))
	secret := [32]byte{1, 2, 3}
	id := strings.Repeat("a", 32)
	st := &testStore{record: api.Record{
		Client:     api.Client{ID: testClientID, Scopes: []string{testScopeRead, testScopeWrite}},
		Credential: api.Credential{ID: "credential", ClientID: testClientID, Scopes: []string{testScopeRead}},
		Secret: api.SecretVersion{
			ID:           id,
			CredentialID: "credential",
			Digest:       sha256.Sum256(secret[:]),
			ExpiresAt:    base.Add(time.Hour),
		},
	}}
	cfg := api.Config{
		Scopes:     []string{testScopeRead, testScopeWrite},
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}
	s, err := api.New(st, cfg, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	rawToken := "api1_" + id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
	advance := func(d time.Duration) { elapsed.Add(int64(d)) }
	return s, st, rawToken, advance
}

func TestUnrelatedClientChangeDoesNotAbortVerification(t *testing.T) {
	for _, factory := range []api.CacheFactory{nil, heldFactory} {
		t.Run(strconv.FormatBool(factory != nil), func(t *testing.T) {
			var opts []api.Option
			if factory != nil {
				opts = append(opts, api.WithCache(factory, time.Minute))
			}
			s, st, token, _ := fixture(t, opts...)
			if factory != nil {
				if err := s.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			st.mu.Lock()
			st.hook = func(_ context.Context, r api.Record) (api.Record, error) {
				//nolint:contextcheck // Unit test exercises background context behavior.
				if err := s.SetClientBanned(context.Background(), "unrelated", true); err != nil {
					return api.Record{}, err
				}
				return r, nil
			}
			st.mu.Unlock()
			if _, err := s.Authenticate(context.Background(), token); err != nil {
				t.Fatalf("unrelated write rejected valid token: %v", err)
			}
			st.mu.Lock()
			reads := st.reads
			st.mu.Unlock()
			if reads != 1 {
				t.Fatalf("unrelated write caused %d reads", reads)
			}
		})
	}
}

func TestRequestCancellationPreservesCause(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		s, st, token, _ := fixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		if errors.Is(cause, context.DeadlineExceeded) {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		if _, err := s.Authenticate(ctx, token); !errors.Is(err, cause) {
			t.Fatalf("pre-canceled: %v", err)
		}
		cancel()
		ctx, cancel = context.WithCancel(context.Background())
		st.mu.Lock()
		st.hook = func(_ context.Context, r api.Record) (api.Record, error) { cancel(); return r, nil }
		st.mu.Unlock()
		if _, err := s.Authenticate(ctx, token); !errors.Is(err, context.Canceled) {
			t.Fatalf("during read: %v", err)
		}
	}
}

type cancelingCache struct {
	source api.Source
	cancel context.CancelFunc
}

func (*cancelingCache) Start(context.Context) error { return nil }

func (*cancelingCache) Close() error { return nil }

func (*cancelingCache) Invalidate() {}

func (c *cancelingCache) Lookup(ctx context.Context, key string, _ uint64) (api.ReadResult, error) {
	r, err := c.source.Lookup(ctx, key)
	c.cancel()
	return r, err
}

func TestCancellationAfterCacheLookupPreservesCause(t *testing.T) {
	var cache *cancelingCache
	s, _, token, _ := fixture(t, api.WithCache(func(source api.Source) (api.Cache, error) {
		cache = &cancelingCache{source: source}
		return cache, nil
	}, time.Minute))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cache.cancel = cancel
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, context.Canceled) || errors.Is(err, api.ErrClosed) {
		t.Fatalf("cache path cancellation: %v", err)
	}
}

func TestAmbiguousWriteInvalidatesCachedDecision(t *testing.T) {
	s, st, token, _ := fixture(t, api.WithCache(heldFactory, time.Minute))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.writeErr = errors.New("commit result unknown")
	st.mu.Unlock()
	if err := s.SetClientBanned(context.Background(), testClientID, true); err == nil {
		t.Fatal("expected ambiguous write error")
	}
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("stale decision after ambiguous write: %v", err)
	}
}

func TestChangeHistoryIsBoundedAndFencesOldReads(t *testing.T) {
	s, st, token, _ := fixture(t, api.WithCache(heldFactory, time.Minute))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	for i := range api.MaxTrackedChanges + 1 {
		s.InvalidateFor(fmt.Sprintf("other-%d", i), "")
	}
	count, unknown := s.TrackedChangesCount()
	if count > api.MaxTrackedChanges || unknown == 0 {
		t.Fatalf("unbounded change history: count=%d unknown=%d", count, unknown)
	}
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	reads := st.reads
	st.mu.Unlock()
	if reads != 2 {
		t.Fatalf("old cached result was not re-read after history reset: reads=%d", reads)
	}
}

func TestStrictLifecycleAndScopes(t *testing.T) {
	s, st, token, advance := fixture(t)
	ctx := context.Background()
	p, err := s.Authenticate(ctx, token, testScopeRead)
	if err != nil || p.ClientID != testClientID {
		t.Fatalf("principal: %+v %v", p, err)
	}
	p.Scopes[0] = testScopeWrite
	if _, err := s.Authenticate(ctx, token, testScopeWrite); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("scope escalation: %v", err)
	}
	if err := s.SetClientScopes(ctx, testClientID, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, testScopeRead); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("scope reduction: %v", err)
	}
	if err := s.SetClientScopes(ctx, testClientID, []string{testScopeRead}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientBanned(ctx, testClientID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("ban: %v", err)
	}
	if err := s.SetClientBanned(ctx, testClientID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); err != nil {
		t.Fatalf("unban: %v", err)
	}
	advance(time.Hour)
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("expiry boundary: %v", err)
	}
	st.mu.Lock()
	st.err = errors.New("database offline")
	st.mu.Unlock()
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, api.ErrUnavailable) {
		t.Fatalf("store failure: %v", err)
	}
}

func TestBoundedStalenessAndIndependentTokenExpiry(t *testing.T) {
	for _, window := range []time.Duration{10 * time.Second, 2 * time.Minute} {
		t.Run(window.String(), func(t *testing.T) {
			s, st, token, advance := fixture(t, api.WithCache(heldFactory, window))
			if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnavailable) {
				t.Fatalf("before Start: %v", err)
			}
			if err := s.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Authenticate(context.Background(), token); err != nil {
				t.Fatal(err)
			}
			// A change on a different replica with a lost event may remain cached.
			st.mu.Lock()
			st.record.Client.Banned = true
			st.err = errors.New("offline")
			st.mu.Unlock()
			advance(window - time.Nanosecond)
			if _, err := s.Authenticate(context.Background(), token); err != nil {
				t.Fatalf("fresh cached lease: %v", err)
			}
			advance(time.Nanosecond)
			if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnavailable) {
				t.Fatalf("stale while offline: %v", err)
			}
			st.mu.Lock()
			st.err = nil
			st.mu.Unlock()
			if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnauthorized) {
				t.Fatalf("recovery: %v", err)
			}
		})
	}
	s, _, token, advance := fixture(t, api.WithCache(heldFactory, 2*time.Hour))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	advance(time.Hour)
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("expiry independent of cache: %v", err)
	}
}

func TestLocalInvalidationFencesDelayedLoad(t *testing.T) {
	s, st, token, _ := fixture(t, api.WithCache(heldFactory, time.Minute))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	st.mu.Lock()
	st.hook = func(ctx context.Context, r api.Record) (api.Record, error) {
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		return r, ctx.Err()
	}
	st.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := s.Authenticate(context.Background(), token); result <- err }()
	<-entered
	if err := s.Revoke(context.Background(), "credential"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("late load resurrected access: %v", err)
	}
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("old cache generation: %v", err)
	}
}

func TestSlowLoadCannotExtendLease(t *testing.T) {
	s, st, token, advance := fixture(t, api.WithCache(heldFactory, 10*time.Second))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.hook = func(_ context.Context, r api.Record) (api.Record, error) { advance(11 * time.Second); return r, nil }
	st.mu.Unlock()
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrUnavailable) {
		t.Fatalf("slow load accepted: %v", err)
	}
}

func TestCloseCancelsAndJoinsVerification(t *testing.T) {
	s, st, token, _ := fixture(t)
	entered := make(chan struct{})
	st.mu.Lock()
	st.hook = func(ctx context.Context, _ api.Record) (api.Record, error) {
		close(entered)
		<-ctx.Done()
		return api.Record{}, ctx.Err()
	}
	st.mu.Unlock()
	finished := make(chan error, 1)
	go func() { _, err := s.Authenticate(context.Background(), token); finished <- err }()
	<-entered
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err == nil {
		t.Fatal("closed verification succeeded")
	}
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, api.ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}

type blockingStartCache struct {
	api.Cache
	entered chan struct{}
}

func (c *blockingStartCache) Start(ctx context.Context) error {
	close(c.entered)
	<-ctx.Done()
	return ctx.Err()
}

func (*blockingStartCache) Close() error { return nil }

func TestCloseCancelsBlockedStart(t *testing.T) {
	entered := make(chan struct{})
	factory := func(api.Source) (api.Cache, error) { return &blockingStartCache{entered: entered}, nil }
	s, st, _, _ := fixture(t, api.WithCache(factory, time.Minute))
	_ = st
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startDone := make(chan error, 1)
	go func() { startDone <- s.Start(ctx) }()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close cannot cancel blocked Start")
	}
	if err := <-startDone; err == nil {
		t.Fatal("canceled Start succeeded")
	}
}

func TestMalformedAndWrongSecretsNeverLeak(t *testing.T) {
	s, _, token, _ := fixture(t)
	badTokens := []string{
		"",
		"Bearer " + token,
		token + "x",
		token[:38] + strings.Repeat("A", 43),
		strings.Repeat("x", 1<<20),
	}
	for _, bad := range badTokens {
		_, err := s.Authenticate(context.Background(), bad)
		if !errors.Is(err, api.ErrUnauthorized) || (len(bad) > 5 && strings.Contains(err.Error(), bad)) {
			t.Fatalf("unsafe invalid-token result: %v", err)
		}
	}
}

func TestConfigurationAndTokenIssuancePolicy(t *testing.T) {
	if _, err := api.New(&testStore{}, api.Config{}); !errors.Is(err, api.ErrInvalid) {
		t.Fatal(err)
	}
	s, st, _, _ := fixture(t)
	_ = st
	for _, ttl := range []time.Duration{-1, 25 * time.Hour} {
		if _, _, err := s.Secret("c", 1, ttl); !errors.Is(err, api.ErrInvalid) {
			t.Fatal(err)
		}
	}
	v, raw, err := s.Secret("c", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, digest, err := api.ParseToken(raw)
	if err != nil || id != v.ID || digest != v.Digest {
		t.Fatal("token generation/parse mismatch")
	}
	if err := s.SetClientScopes(context.Background(), testClientID, []string{"unknown"}); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func FuzzTokenParser(f *testing.F) {
	f.Add("")
	f.Add("api1_" + strings.Repeat("a", 32) + "." + strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, raw string) {
		id, _, err := api.ParseToken(raw)
		if err == nil && len(id) != 32 {
			t.Fatal("invalid lookup ID")
		}
	})
}
