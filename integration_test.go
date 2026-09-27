package api_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/assurrussa/api/postgres"
)

const (
	testScopeRead           = "read"
	testScopeWrite          = "write"
	testTableSecretVersions = "secret_versions"
	testModeArc             = "arc"
	testModeRcu             = "rcu"
)

func database(tb testing.TB) (*postgres.Store, *pgxpool.Pool, string) {
	tb.Helper()
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		tb.Skip("API_TEST_DATABASE_URL required for PostgreSQL integration")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		tb.Fatal(err)
	}
	schema := "api_runtime_" + strings.ToLower(rand.Text())
	store, err := postgres.New(pool, schema)
	if err != nil {
		pool.Close()
		tb.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		pool.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		pool.Close()
		if err != nil {
			tb.Errorf("schema cleanup: %v", err)
		}
	})
	return store, pool, schema
}

func newService(tb testing.TB, store api.Store, options ...api.Option) *api.Service {
	tb.Helper()
	cfg := api.Config{
		Scopes:     []string{testScopeRead, testScopeWrite},
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}
	s, err := api.New(store, cfg, options...)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

func requireAuth(tb testing.TB, s *api.Service, token string, want error, scopes ...string) {
	tb.Helper()
	_, err := s.Authenticate(context.Background(), token, scopes...)
	if !errors.Is(err, want) {
		tb.Fatalf("authentication error=%v want=%v", err, want)
	}
}

func TestPostgresServiceLifecycle(t *testing.T) {
	store, pool, schema := database(t)
	s := newService(t, store)
	ctx := context.Background()
	client, err := s.CreateClient(ctx, "warehouse", []string{testScopeRead, "write"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.Issue(ctx, api.IssueRequest{ClientID: client.ID, Name: "reader", Scopes: []string{testScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	requireAuth(t, s, issued.Token, nil, testScopeRead)
	requireAuth(t, s, issued.Token, api.ErrForbidden, "write")
	badReq := api.IssueRequest{ClientID: client.ID, Name: "bad", TTL: 25 * time.Hour}
	if _, err := s.Issue(ctx, badReq); !errors.Is(err, api.ErrInvalid) {
		t.Fatal(err)
	}
	rotateReq := api.RotateRequest{CredentialID: issued.Credential.ID, ExpectedGeneration: 1, GracePeriod: time.Minute}
	rotated, err := s.Rotate(ctx, rotateReq)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Credential.ID != issued.Credential.ID || rotated.Credential.Generation != 2 {
		t.Fatal("rotation changed identity")
	}
	requireAuth(t, s, issued.Token, nil)
	requireAuth(t, s, rotated.Token, nil)
	// Another rotation must not extend the oldest transition deadline.
	var deadline time.Time
	queryDeadline := "SELECT expires_at FROM " + pgx.Identifier{schema, testTableSecretVersions}.Sanitize() +
		" WHERE credential_id=$1 AND generation=1"
	if err := pool.QueryRow(ctx, queryDeadline, issued.Credential.ID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	third, err := s.Rotate(ctx, api.RotateRequest{CredentialID: issued.Credential.ID, ExpectedGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	requireAuth(t, s, rotated.Token, api.ErrUnauthorized)
	requireAuth(t, s, third.Token, nil)
	var still time.Time
	if err := pool.QueryRow(ctx, queryDeadline, issued.Credential.ID).Scan(&still); err != nil || !still.Equal(deadline) {
		t.Fatalf("old deadline extended: %v", err)
	}
	if err := s.SetClientBanned(ctx, client.ID, true); err != nil {
		t.Fatal(err)
	}
	requireAuth(t, s, third.Token, api.ErrUnauthorized)
	if _, err := s.Issue(ctx, api.IssueRequest{ClientID: client.ID, Name: "banned"}); !errors.Is(err, api.ErrForbidden) {
		t.Fatal(err)
	}
	if err := s.SetClientBanned(ctx, client.ID, false); err != nil {
		t.Fatal(err)
	}
	requireAuth(t, s, third.Token, nil)
	if err := s.Revoke(ctx, issued.Credential.ID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{issued.Token, rotated.Token, third.Token} {
		requireAuth(t, s, token, api.ErrUnauthorized)
	}
	conflictReq := api.RotateRequest{CredentialID: issued.Credential.ID, ExpectedGeneration: 3}
	if _, err := s.Rotate(ctx, conflictReq); !errors.Is(err, api.ErrConflict) {
		t.Fatal(err)
	}
	otherStore, _, _ := database(t)
	other := newService(t, otherStore)
	requireAuth(t, other, third.Token, api.ErrUnauthorized)
	clients, err := s.Clients(ctx, "", 1)
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients: %v", err)
	}
	grants, err := s.Credentials(ctx, client.ID, "", 10)
	if err != nil || len(grants) != 1 || grants[0].RevokedAt == nil {
		t.Fatalf("credentials: %+v %v", grants, err)
	}
}

type observedStore struct {
	api.Store
	watcher api.Watcher
	events  chan struct{}
}

func (o *observedStore) Watch(ctx context.Context, invalidate func()) error {
	return o.watcher.Watch(ctx, func() {
		invalidate()
		select {
		case o.events <- struct{}{}:
		default:
		}
	})
}

func awaitEvent(t *testing.T, events <-chan struct{}) {
	t.Helper()
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("notification not delivered")
	}
}

func TestPostgresTwoInstances(t *testing.T) {
	for name, factory := range map[string]api.CacheFactory{testModeArc: arc.Factory(128), testModeRcu: rcu.Factory(time.Minute)} {
		t.Run(name, func(t *testing.T) {
			store, _, _ := database(t)
			writer := newService(t, store)
			ctx := context.Background()
			client, err := writer.CreateClient(ctx, "client", []string{testScopeRead, testScopeWrite})
			if err != nil {
				t.Fatal(err)
			}
			issueReq := api.IssueRequest{ClientID: client.ID, Name: "access", Scopes: []string{testScopeRead, testScopeWrite}}
			issued, err := writer.Issue(ctx, issueReq)
			if err != nil {
				t.Fatal(err)
			}
			observed := &observedStore{Store: store, watcher: store, events: make(chan struct{}, 32)}
			reader := newService(t, observed, api.WithCache(factory, 2*time.Minute))
			if err := reader.Start(ctx); err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, issued.Token, nil, testScopeWrite)
			if err := writer.SetClientScopes(ctx, client.ID, []string{testScopeRead}); err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, issued.Token, api.ErrForbidden, testScopeWrite)
			requireAuth(t, reader, issued.Token, nil, testScopeRead)
			rotated, err := writer.Rotate(ctx, api.RotateRequest{CredentialID: issued.Credential.ID, ExpectedGeneration: 1})
			if err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, issued.Token, api.ErrUnauthorized)
			requireAuth(t, reader, rotated.Token, nil, testScopeRead)
			if err := writer.SetClientBanned(ctx, client.ID, true); err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, rotated.Token, api.ErrUnauthorized)
			if err := writer.SetClientBanned(ctx, client.ID, false); err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, rotated.Token, nil)
			if err := writer.RevokeAll(ctx, client.ID); err != nil {
				t.Fatal(err)
			}
			awaitEvent(t, observed.events)
			requireAuth(t, reader, rotated.Token, api.ErrUnauthorized)
		})
	}
}
