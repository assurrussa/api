package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
)

func TestManagedServiceOperationRecovery(t *testing.T) {
	store, _, _ := database(t)
	s := newService(t, store, api.WithAudit(), api.WithUsageTracking(api.UsageConfig{}))
	ctx := api.WithActor(context.Background(), api.Actor{Kind: "human", ID: "operator"})
	client, err := s.CreateClient(ctx, "integration", []string{testScopeRead, testScopeWrite})
	if err != nil {
		t.Fatal(err)
	}
	req := api.IssueRequest{ClientID: client.ID, Name: "managed-reader", Scopes: []string{testScopeRead}, TTL: 0}
	const count = 6
	results := make(chan api.OperationResult, count)
	failures := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() { result, e := s.IssueOnce(ctx, "issue-1", req); results <- result; failures <- e })
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first api.OperationResult
	issued := 0
	for r := range results {
		if r.Issued != nil {
			issued++
			first = r
		}
	}
	if issued != 1 {
		t.Fatalf("plaintext responses=%d", issued)
	}
	if _, err = s.Authenticate(ctx, first.Issued.Token, testScopeWrite); !errors.Is(err, api.ErrForbidden) {
		t.Fatal(err)
	}
	rotated, err := s.RotateOnce(ctx, "rotate-1", api.RotateRequest{
		CredentialID: first.Receipt.Credential.ID, ExpectedGeneration: 1, GracePeriod: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Issued == nil {
		t.Fatal("missing first rotation token")
	}
	if err = s.SetClientBanned(ctx, client.ID, true); err != nil {
		t.Fatal(err)
	}
	// A completed logical request is replayed despite later policy/config changes.
	other, err := api.New(store, api.Config{DefaultTTL: time.Second, MaxTTL: time.Second}, api.WithAudit())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	replay, err := other.IssueOnce(ctx, "issue-1", req)
	if err != nil || replay.Issued != nil || replay.Receipt.Credential.ID != first.Receipt.Credential.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	wrongActor := api.WithActor(context.Background(), api.Actor{Kind: "service", ID: "other"})
	if _, err = other.IssueOnce(wrongActor, "issue-1", req); !errors.Is(err, api.ErrConflict) {
		t.Fatal(err)
	}
	changed := req
	changed.Name = "other"
	if _, err = other.IssueOnce(ctx, "issue-1", changed); !errors.Is(err, api.ErrConflict) {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	details, err := store.CredentialDetails(ctx, first.Receipt.Credential.ID)
	if err != nil || details.LastUsedAt == nil {
		t.Fatalf("last used missing: %+v %v", details, err)
	}
	events, err := store.AuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("audit duplicated or missing: %d", len(events))
	}
	body, err := json.Marshal(struct {
		Receipt api.OperationReceipt `json:"receipt"`
		Events  []api.AuditEvent     `json:"events"`
	}{first.Receipt, events})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), first.Issued.Token) ||
		strings.Contains(string(body), "digest") || strings.Contains(string(body), "fingerprint") {
		t.Fatal("verification material leaked")
	}
}

func TestManagedRetirementInEveryCacheMode(t *testing.T) {
	for _, mode := range []string{"strict", "arc", "rcu"} {
		t.Run(mode, func(t *testing.T) {
			store, _, _ := database(t)
			var options []api.Option
			switch mode {
			case "arc":
				options = append(options, api.WithCache(arc.Factory(10), time.Second))
			case "rcu":
				options = append(options, api.WithCache(rcu.Factory(100*time.Millisecond), time.Second))
			}
			s := newService(t, store, options...)
			ctx := context.Background()
			client, err := s.CreateClient(ctx, "integration", []string{testScopeRead})
			if err != nil {
				t.Fatal(err)
			}
			first, err := s.Issue(ctx, api.IssueRequest{ClientID: client.ID, Name: "managed-reader", Scopes: []string{testScopeRead}})
			if err != nil {
				t.Fatal(err)
			}
			second, err := s.Rotate(ctx, api.RotateRequest{
				CredentialID: first.Credential.ID, ExpectedGeneration: 1, GracePeriod: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Start(ctx); err != nil {
				t.Fatal(err)
			}
			requireAuth(t, s, first.Token, nil)
			versions, err := s.SecretVersions(ctx, first.Credential.ID, 0, 100)
			if err != nil || len(versions) != 2 {
				t.Fatalf("versions=%v %v", versions, err)
			}
			if err = s.RetireVersion(ctx, first.Credential.ID, versions[0].ID); !errors.Is(err, api.ErrConflict) {
				t.Fatal(err)
			}
			if err = s.RetireVersion(ctx, first.Credential.ID, versions[1].ID); err != nil {
				t.Fatal(err)
			}
			requireAuth(t, s, first.Token, api.ErrUnauthorized)
			requireAuth(t, s, second.Token, nil)
		})
	}
}

// lostOperationStore simulates a committed write whose response never reaches
// Service. The real PostgreSQL receipt remains the authority for recovery.
type lostOperationStore struct {
	api.Store
	api.OperationStore
}

func (st lostOperationStore) IssueOnce(
	ctx context.Context, spec api.OperationSpec, c api.Credential, v api.SecretVersion, ttl time.Duration,
) (api.OperationReceipt, bool, error) {
	if _, _, err := st.OperationStore.IssueOnce(ctx, spec, c, v, ttl); err != nil {
		return api.OperationReceipt{}, false, err
	}
	return api.OperationReceipt{}, false, errors.New("commit result lost")
}

func TestManagedLostCommitResponseRecovery(t *testing.T) {
	store, _, _ := database(t)
	admin := newService(t, store)
	ctx := context.Background()
	client, err := admin.CreateClient(ctx, "lost-response-client", nil)
	if err != nil {
		t.Fatal(err)
	}
	losing := newService(t, lostOperationStore{Store: store, OperationStore: store})
	req := api.IssueRequest{ClientID: client.ID, Name: "lost-key"}
	result, err := losing.IssueOnce(ctx, "lost-response", req)
	if err == nil || result.Issued != nil {
		t.Fatalf("unexpected response %+v %v", result, err)
	}
	receipt, err := admin.Operation(ctx, "lost-response")
	if err != nil {
		t.Fatal(err)
	}
	// Empty and nil scope sets represent the same logical administrative request.
	req.Scopes = []string{}
	repeated, err := admin.IssueOnce(ctx, "lost-response", req)
	if err != nil || repeated.Issued != nil || repeated.Receipt.Credential.ID != receipt.Credential.ID {
		t.Fatalf("recovery %+v %v", repeated, err)
	}
	fresh, err := admin.RotateOnce(ctx, "recover-secret", api.RotateRequest{
		CredentialID: receipt.Credential.ID, ExpectedGeneration: receipt.Credential.Generation,
	})
	if err != nil || fresh.Issued == nil {
		t.Fatalf("rotation %+v %v", fresh, err)
	}
	requireAuth(t, admin, fresh.Issued.Token, nil)
}
