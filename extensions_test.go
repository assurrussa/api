package api_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/assurrussa/api"
)

type usageStore struct {
	*testStore
	usageMu      sync.Mutex
	observations []api.UsageObservation
	failure      error
}

func (st *usageStore) RecordUsage(_ context.Context, batch []api.UsageObservation) error {
	st.usageMu.Lock()
	defer st.usageMu.Unlock()
	if st.failure != nil {
		return st.failure
	}
	st.observations = append(st.observations, batch...)
	return nil
}

func usageFixture(t *testing.T, cfg api.UsageConfig) (*api.Service, *usageStore, string) {
	t.Helper()
	_, base, token, _ := fixture(t)
	store := &usageStore{testStore: base}
	s, err := api.New(store, api.Config{
		Scopes: []string{testScopeRead, testScopeWrite}, DefaultTTL: time.Hour, MaxTTL: time.Hour,
	}, api.WithUsageTracking(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, store, token
}

func TestUsageTracksForbiddenAndFlushesAtClose(t *testing.T) {
	s, store, token := usageFixture(t, api.UsageConfig{})
	if _, err := s.Authenticate(context.Background(), token, testScopeWrite); !errors.Is(err, api.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(context.Background(), "invalid"); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatal(err)
	}
	if s.UsageStats().Pending != 1 {
		t.Fatal(s.UsageStats())
	}
	details, err := s.AuthenticateDetails(context.Background(), token, testScopeRead)
	if err != nil || details.SecretVersionID != store.record.Secret.ID ||
		details.Principal.CredentialID != store.record.Credential.ID {
		t.Fatalf("%+v %v", details, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	store.usageMu.Lock()
	defer store.usageMu.Unlock()
	if len(store.observations) != 1 || store.observations[0].VersionID != details.SecretVersionID {
		t.Fatal(store.observations)
	}
	if s.UsageStats().Pending != 0 {
		t.Fatal(s.UsageStats())
	}
}

func TestUsageFailureNeverDeniesAndCloseReports(t *testing.T) {
	s, store, token := usageFixture(t, api.UsageConfig{})
	cause := errors.New("statistics unavailable")
	store.failure = cause
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.Is(err, cause) {
		t.Fatalf("close: %v", err)
	}
	if s.UsageStats().Pending != 1 {
		t.Fatal(s.UsageStats())
	}
}

func TestUsageBoundedPendingAndWorker(t *testing.T) {
	s, store, token := usageFixture(t, api.UsageConfig{MaxPending: 1, FlushInterval: time.Millisecond})
	if _, err := s.Authenticate(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.record.Secret.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	store.mu.Unlock()
	other := "api1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." + token[38:]
	if _, err := s.Authenticate(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if stats := s.UsageStats(); stats.Pending != 1 || stats.Dropped != 1 {
		t.Fatal(stats)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.UsageStats().LastFlushAt.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no usage flush")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOptionalCapabilitiesFailBeforeWork(t *testing.T) {
	cfg := api.Config{DefaultTTL: time.Hour, MaxTTL: time.Hour}
	for _, opt := range []api.Option{api.WithAudit(), api.WithUsageTracking(api.UsageConfig{})} {
		if _, err := api.New(&testStore{}, cfg, opt); !errors.Is(err, api.ErrUnsupported) {
			t.Fatal(err)
		}
	}
	s, err := api.New(&testStore{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CredentialDetails(context.Background(), "x"); !errors.Is(err, api.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := s.IssueOnce(context.Background(), "op", api.IssueRequest{}); !errors.Is(err, api.ErrUnsupported) {
		t.Fatal(err)
	}
}

type auditedSpy struct {
	api.Store
	calls int
}

func (st *auditedSpy) CreateClientAudited(_ context.Context, _ api.Actor, _ api.Client) error {
	st.calls++
	return nil
}

func (st *auditedSpy) SetClientScopesAudited(_ context.Context, _ api.Actor, _ string, _ []string) error {
	st.calls++
	return nil
}

func (st *auditedSpy) SetClientBannedAudited(_ context.Context, _ api.Actor, _ string, _ bool) error {
	st.calls++
	return nil
}

func (st *auditedSpy) IssueAudited(_ context.Context, _ api.Actor, _ api.Credential, _ api.SecretVersion) error {
	st.calls++
	return nil
}

func (st *auditedSpy) RotateAudited(
	_ context.Context, _ api.Actor, _ string, _ int64, _ api.SecretVersion, _ time.Duration, _ time.Time,
) (api.Credential, error) {
	st.calls++
	return api.Credential{}, nil
}

func (st *auditedSpy) RevokeAudited(_ context.Context, _ api.Actor, _ string, _ time.Time) error {
	st.calls++
	return nil
}

func (st *auditedSpy) RevokeAllAudited(_ context.Context, _ api.Actor, _ string, _ time.Time) error {
	st.calls++
	return nil
}

func TestAuditRequiresActorAndRoutesEveryMutation(t *testing.T) {
	store := &auditedSpy{}
	s, err := api.New(store, api.Config{Scopes: []string{testScopeRead}, DefaultTTL: time.Hour, MaxTTL: time.Hour}, api.WithAudit())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	calls := []func(context.Context) error{
		func(ctx context.Context) error { _, e := s.CreateClient(ctx, "client", nil); return e },
		func(ctx context.Context) error { return s.SetClientScopes(ctx, "client", nil) },
		func(ctx context.Context) error { return s.SetClientBanned(ctx, "client", true) },
		func(ctx context.Context) error {
			_, e := s.Issue(ctx, api.IssueRequest{ClientID: "client", Name: "key"})
			return e
		},
		func(ctx context.Context) error {
			_, e := s.Rotate(ctx, api.RotateRequest{CredentialID: "key", ExpectedGeneration: 1})
			return e
		},
		func(ctx context.Context) error { return s.Revoke(ctx, "key") },
		func(ctx context.Context) error { return s.RevokeAll(ctx, "client") },
	}
	for _, call := range calls {
		if err := call(context.Background()); !errors.Is(err, api.ErrInvalid) {
			t.Fatal(err)
		}
	}
	if store.calls != 0 {
		t.Fatal("unaudited writes", store.calls)
	}
	ctx := api.WithActor(context.Background(), api.Actor{Kind: "service", ID: "job"})
	for _, call := range calls {
		if err := call(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if store.calls != len(calls) {
		t.Fatal("wrong routing", store.calls)
	}
}
