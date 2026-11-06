package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/assurrussa/api/postgres"
)

func TestPostgresPermanentLifecycle(t *testing.T) {
	for _, mode := range []string{"uncached", testModeArc, testModeRcu} {
		t.Run(mode, func(t *testing.T) {
			store, pool, schema := database(t)
			options := []api.Option{api.WithNonExpiring(), api.WithAudit()}
			if mode == testModeArc {
				options = append(options, api.WithCache(arc.Factory(32), time.Second))
			}
			if mode == testModeRcu {
				options = append(options, api.WithCache(rcu.Factory(time.Millisecond*20), time.Second))
			}
			s := newService(t, store, options...)
			ctx := api.WithActor(context.Background(), api.Actor{Kind: "human", ID: "operator"})
			if err := s.Start(ctx); err != nil {
				t.Fatal(err)
			}
			client, err := s.CreateClient(ctx, "permanent", []string{testScopeRead})
			if err != nil {
				t.Fatal(err)
			}
			req := api.IssueRequest{ClientID: client.ID, Name: "permanent", Scopes: []string{testScopeRead}, NonExpiring: true}
			bad := req
			bad.TTL = time.Hour
			if _, err = s.Issue(ctx, bad); !errors.Is(err, api.ErrInvalid) {
				t.Fatal(err)
			}
			result, err := s.IssueOnce(ctx, "permanent-issue", req)
			if err != nil {
				t.Fatal(err)
			}
			issued := *result.Issued
			if !issued.NonExpiring || !issued.ExpiresAt.IsZero() || !result.Receipt.Version.NonExpiring {
				t.Fatalf("issue=%+v", result)
			}
			requirePermanentStorage(ctx, t, s, store, pool, schema, result)
			requireAuth(t, s, issued.Token, nil)
			verifier := newService(t, store, api.WithClock(func() time.Time { return time.Now().Add(100 * 365 * 24 * time.Hour) }))
			requireAuth(t, verifier, issued.Token, nil)
			replayService := newService(t, store, api.WithAudit())
			requirePermanentReplay(ctx, t, s, replayService, req)
			current := rotatePermanentTransitions(ctx, t, s, issued)
			versions, err := s.SecretVersions(ctx, issued.Credential.ID, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.RetireVersion(ctx, issued.Credential.ID, versions[len(versions)-1].ID); err != nil {
				t.Fatal(err)
			}
			requireAuth(t, s, issued.Token, api.ErrUnauthorized)
			requirePermanentAudit(ctx, t, s)
			requirePermanentRevocation(ctx, t, s, client.ID, current)
		})
	}
}

func TestPostgresPermanentConcurrentRotation(t *testing.T) {
	store, _, _ := database(t)
	s := newService(t, store, api.WithNonExpiring())
	ctx := context.Background()
	client, err := s.CreateClient(ctx, "concurrent", nil)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.Issue(ctx, api.IssueRequest{ClientID: client.ID, Name: "permanent", NonExpiring: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var successes atomic.Int64
	for i := range 8 {
		wg.Go(func() {
			_, e := s.RotateOnce(ctx, fmt.Sprintf("rotate-%d", i), api.RotateRequest{
				CredentialID: issued.Credential.ID, ExpectedGeneration: 1, NonExpiring: true, GracePeriod: time.Hour,
			})
			if e == nil {
				successes.Add(1)
			} else if !errors.Is(e, api.ErrConflict) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful rotations=%d", successes.Load())
	}
}

func rotatePermanentTransitions(ctx context.Context, t *testing.T, s *api.Service, issued api.Issued) api.Issued {
	t.Helper()
	// Permanent -> finite -> permanent -> permanent, preserving older grace deadlines.
	current := issued
	var firstDeadline time.Time
	for i, permanent := range []bool{false, true, true} {
		next, e := s.Rotate(ctx, api.RotateRequest{
			CredentialID: issued.Credential.ID, ExpectedGeneration: current.Credential.Generation,
			NonExpiring: permanent, GracePeriod: time.Hour,
		})
		if e != nil {
			t.Fatal(e)
		}
		if next.NonExpiring != permanent || next.ExpiresAt.IsZero() != permanent {
			t.Fatalf("rotation=%+v", next)
		}
		versions, e := s.SecretVersions(ctx, issued.Credential.ID, 0, 10)
		if e != nil {
			t.Fatal(e)
		}
		if versions[1].NonExpiring || versions[1].ExpiresAt.IsZero() {
			t.Fatal("preceding current not retired")
		}
		if i == 0 {
			firstDeadline = versions[1].ExpiresAt
		} else if !versions[len(versions)-1].ExpiresAt.Equal(firstDeadline) {
			t.Fatal("older grace extended")
		}
		if _, err := s.Authenticate(ctx, current.Token); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	return current
}

func requirePermanentAudit(ctx context.Context, t *testing.T, s *api.Service) {
	t.Helper()
	events, err := s.AuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("empty audit")
	}
	found := false
	for _, event := range events {
		if event.Action == "credential.issue" {
			found, _ = event.Details["non_expiring"].(bool)
		}
	}
	if !found {
		t.Fatalf("permanent audit missing: %s", body)
	}
}

func requirePermanentStorage(
	ctx context.Context, t *testing.T, s *api.Service, store *postgres.Store, pool *pgxpool.Pool,
	schema string, result api.OperationResult,
) {
	t.Helper()
	var nullExpiry bool
	query := `SELECT expires_at IS NULL FROM ` + fmt.Sprintf("%q.secret_versions", schema) + ` WHERE credential_id=$1`
	err := pool.QueryRow(ctx, query, result.Receipt.Credential.ID).Scan(&nullExpiry)
	if err != nil || !nullExpiry {
		t.Fatalf("null=%v err=%v", nullExpiry, err)
	}
	details, err := s.CredentialDetails(ctx, result.Receipt.Credential.ID)
	if err != nil || !details.CurrentVersion.NonExpiring || details.UnexpiredVersions != 1 {
		t.Fatalf("details=%+v %v", details, err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot[result.Receipt.Version.ID].Secret.NonExpiring {
		t.Fatal("permanent omitted from snapshot")
	}
	if n, e := store.PruneExpiredVersions(ctx, time.Now().Add(-time.Second), 100); e != nil || n != 0 {
		t.Fatalf("prune=%d %v", n, e)
	}
}

func requirePermanentReplay(ctx context.Context, t *testing.T, s, replayService *api.Service, req api.IssueRequest) {
	t.Helper()
	replay, err := replayService.IssueOnce(ctx, "permanent-issue", req)
	if err != nil || replay.Issued != nil || !replay.Receipt.Version.NonExpiring {
		t.Fatalf("replay=%+v %v", replay, err)
	}
	finiteReq := req
	finiteReq.NonExpiring = false
	if _, err = s.IssueOnce(ctx, "permanent-issue", finiteReq); !errors.Is(err, api.ErrConflict) {
		t.Fatal(err)
	}
}

func requirePermanentRevocation(ctx context.Context, t *testing.T, s *api.Service, clientID string, current api.Issued) {
	t.Helper()
	if err := s.SetClientBanned(ctx, clientID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, current.Token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := s.SetClientBanned(ctx, clientID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, current.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, current.Token); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatal(err)
	}
}
