package api_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
)

func TestManagedScopeOrderAndDuplicatesReplayTheSameOperation(t *testing.T) {
	store, _, _ := database(t)
	s := newService(t, store)
	ctx := context.Background()
	client, err := s.CreateClient(ctx, "scope-normalization", []string{testScopeRead, testScopeWrite})
	if err != nil {
		t.Fatal(err)
	}
	input := []string{testScopeWrite, testScopeRead, testScopeWrite}
	original := slices.Clone(input)
	first, err := s.IssueOnce(ctx, "normalized-scopes", api.IssueRequest{ClientID: client.ID, Name: "normalized-key", Scopes: input})
	if err != nil || first.Issued == nil {
		t.Fatalf("issue: %+v %v", first, err)
	}
	if !slices.Equal(input, original) {
		t.Fatal("IssueOnce mutated caller scopes")
	}
	replay, err := s.IssueOnce(ctx, "normalized-scopes", api.IssueRequest{
		ClientID: client.ID, Name: "normalized-key", Scopes: []string{testScopeRead, testScopeWrite},
	})
	if err != nil || replay.Issued != nil || replay.Receipt.Version.ID != first.Receipt.Version.ID {
		t.Fatalf("replay: %+v %v", replay, err)
	}
}

func TestRetirementPropagatesToAnotherCachedService(t *testing.T) {
	for _, mode := range []string{testModeArc, testModeRcu} {
		t.Run(mode, func(t *testing.T) {
			store, _, _ := database(t)
			admin := newService(t, store)
			ctx := context.Background()
			client, err := admin.CreateClient(ctx, "retirement-replicas", []string{testScopeRead})
			if err != nil {
				t.Fatal(err)
			}
			first, err := admin.Issue(ctx, api.IssueRequest{ClientID: client.ID, Name: "replica-key", Scopes: []string{testScopeRead}})
			if err != nil {
				t.Fatal(err)
			}
			second, err := admin.Rotate(ctx, api.RotateRequest{
				CredentialID: first.Credential.ID, ExpectedGeneration: 1, GracePeriod: time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			const maxAge = 200 * time.Millisecond
			var option api.Option
			if mode == testModeArc {
				option = api.WithCache(arc.Factory(10), maxAge)
			} else {
				option = api.WithCache(rcu.Factory(20*time.Millisecond), maxAge)
			}
			verifier := newService(t, store, option)
			if err = verifier.Start(ctx); err != nil {
				t.Fatal(err)
			}
			requireAuth(t, verifier, first.Token, nil)
			versions, err := admin.SecretVersions(ctx, first.Credential.ID, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if err = admin.RetireVersion(ctx, first.Credential.ID, versions[1].ID); err != nil {
				t.Fatal(err)
			}
			waitRetirement(t, verifier, first.Token, maxAge)
			requireAuth(t, verifier, second.Token, nil)
		})
	}
}

func waitRetirement(t *testing.T, verifier *api.Service, token string, maxAge time.Duration) {
	t.Helper()
	ctx := t.Context()
	deadline := time.NewTimer(maxAge + time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		_, err := verifier.Authenticate(ctx, token, testScopeRead)
		if errors.Is(err, api.ErrUnauthorized) {
			break
		}
		if err != nil {
			t.Fatalf("verification after retirement: %v", err)
		}
		select {
		case <-deadline.C:
			t.Fatal("other replica trusted retired version beyond staleness budget")
		case <-poll.C:
		}
	}
}
