package api_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/assurrussa/api"
)

const (
	adminContractCredentialID = "admin-contract-credential"
	adminContractName         = "admin-contract"
)

// Embedding only Store keeps the compatibility path distinct from TimedStore.
type adminContractStore struct {
	api.Store
	credential api.Credential
	version    api.SecretVersion
	method     string
	calls      int
	ttl        time.Duration
	grace      time.Duration
	expected   int64
	at         time.Time
	err        error
}

func (st *adminContractStore) Issue(_ context.Context, credential api.Credential, version api.SecretVersion) error {
	st.method = "Issue"
	st.calls++
	st.credential, st.version = credential, version
	return st.err
}

func (st *adminContractStore) Rotate(
	_ context.Context, id string, expected int64, version api.SecretVersion, grace time.Duration, at time.Time,
) (api.Credential, error) {
	st.method = "Rotate"
	st.calls++
	st.version, st.expected, st.grace, st.at = version, expected, grace, at
	credential := st.credential
	credential.ID, credential.Generation = id, version.Generation
	return credential, st.err
}

type timedAdminContractStore struct{ *adminContractStore }

func (st timedAdminContractStore) IssueWithLifetime(
	_ context.Context, credential api.Credential, version api.SecretVersion, ttl time.Duration,
) (api.Credential, api.SecretVersion, error) {
	st.method = "IssueWithLifetime"
	st.calls++
	st.ttl = ttl
	// Simulate time spent acquiring authority locks. The service must return
	// the actual committed timestamps, not the earlier values it generated.
	credential.CreatedAt = credential.CreatedAt.Add(time.Minute)
	version.CreatedAt = credential.CreatedAt
	version.ExpiresAt = version.CreatedAt.Add(ttl)
	st.credential, st.version = credential, version
	if st.err != nil {
		return api.Credential{}, api.SecretVersion{}, st.err
	}
	return credential, version, nil
}

func (st timedAdminContractStore) RotateWithLifetime(
	_ context.Context, id string, expected int64, version api.SecretVersion, ttl, grace time.Duration,
) (api.Credential, api.SecretVersion, error) {
	st.method = "RotateWithLifetime"
	st.calls++
	st.ttl, st.expected, st.grace = ttl, expected, grace
	version.CreatedAt = version.CreatedAt.Add(time.Minute)
	version.ExpiresAt = version.CreatedAt.Add(ttl)
	st.version, st.at = version, version.CreatedAt
	credential := st.credential
	credential.ID, credential.Generation = id, version.Generation
	if st.err != nil {
		return api.Credential{}, api.SecretVersion{}, st.err
	}
	return credential, version, nil
}

func newAdminContractService(t *testing.T, timed bool) (*api.Service, *adminContractStore, time.Time) {
	t.Helper()
	at := time.Date(2026, time.October, 2, 12, 0, 0, 0, time.UTC)
	st := &adminContractStore{credential: api.Credential{
		ID: adminContractCredentialID, ClientID: testClientID, Name: "existing", Scopes: []string{testScopeRead}, Generation: 3,
		CreatedAt: at.Add(-time.Hour),
	}}
	var store api.Store = st
	if timed {
		store = timedAdminContractStore{st}
	}
	s, err := api.New(store, api.Config{
		Scopes: []string{testScopeRead, testScopeWrite}, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour,
	}, api.WithClock(func() time.Time { return at }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, st, at
}

func checkIssuedSecret(t *testing.T, issued api.Issued, version api.SecretVersion, createdAt time.Time, ttl time.Duration) {
	t.Helper()
	id, digest, err := api.ParseToken(issued.Token)
	if err != nil || id != version.ID || digest != version.Digest {
		t.Fatal("returned token does not match stored verification material")
	}
	if !version.CreatedAt.Equal(createdAt) || !version.ExpiresAt.Equal(createdAt.Add(ttl)) ||
		!issued.ExpiresAt.Equal(version.ExpiresAt) {
		t.Fatal("returned or stored secret timestamps do not match the store contract")
	}
	if version.CredentialID != issued.Credential.ID || version.Generation != issued.Credential.Generation {
		t.Fatal("returned credential does not match the stored secret version")
	}
}

type adminContractCase struct {
	name  string
	timed bool
	ttl   time.Duration
}

func adminContractCases() []adminContractCase {
	return []adminContractCase{
		{name: "store_default"},
		{name: "store_explicit", ttl: 2 * time.Hour},
		{name: "timed_default", timed: true},
		{name: "timed_explicit", timed: true, ttl: 2 * time.Hour},
	}
}

func TestIssueStoreContracts(t *testing.T) {
	for _, tc := range adminContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			s, st, at := newAdminContractService(t, tc.timed)
			scopes := []string{testScopeWrite, testScopeRead, testScopeRead}
			issued, err := s.Issue(context.Background(), api.IssueRequest{
				ClientID: testClientID, Name: adminContractName, Scopes: scopes, TTL: tc.ttl,
			})
			if err != nil {
				t.Fatal(err)
			}
			ttl, method := tc.ttl, "Issue"
			if ttl == 0 {
				ttl = time.Hour
			}
			if tc.timed {
				at, method = at.Add(time.Minute), "IssueWithLifetime"
				if st.ttl != ttl {
					t.Fatalf("timed lifetime=%v, want %v", st.ttl, ttl)
				}
			}
			if st.calls != 1 || st.method != method {
				t.Fatalf("dispatch=%s calls=%d, want %s once", st.method, st.calls, method)
			}
			checkIssuedSecret(t, issued, st.version, at, ttl)
			if issued.Credential.ID == "" || issued.Credential.ClientID != testClientID ||
				issued.Credential.Name != adminContractName || issued.Credential.Generation != 1 ||
				!issued.Credential.CreatedAt.Equal(at) ||
				!slices.Equal(issued.Credential.Scopes, []string{testScopeRead, testScopeWrite}) {
				t.Fatal("credential metadata was not preserved")
			}
			if !slices.Equal(scopes, []string{testScopeWrite, testScopeRead, testScopeRead}) {
				t.Fatal("issuance mutated the caller's scopes")
			}
		})
	}
}

func TestRotateStoreContracts(t *testing.T) {
	for _, tc := range adminContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			s, st, at := newAdminContractService(t, tc.timed)
			before := st.credential
			issued, err := s.Rotate(context.Background(), api.RotateRequest{
				CredentialID: before.ID, ExpectedGeneration: 3, TTL: tc.ttl, GracePeriod: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			ttl, method := tc.ttl, "Rotate"
			if ttl == 0 {
				ttl = time.Hour
			}
			if tc.timed {
				at, method = at.Add(time.Minute), "RotateWithLifetime"
				if st.ttl != ttl {
					t.Fatalf("timed lifetime=%v, want %v", st.ttl, ttl)
				}
			}
			if st.calls != 1 || st.method != method || st.expected != 3 || st.grace != time.Minute || !st.at.Equal(at) {
				t.Fatal("rotation dispatch or arguments changed")
			}
			checkIssuedSecret(t, issued, st.version, at, ttl)
			if issued.Credential.ID != before.ID || issued.Credential.ClientID != before.ClientID ||
				issued.Credential.Name != before.Name || issued.Credential.Generation != 4 ||
				!issued.Credential.CreatedAt.Equal(before.CreatedAt) || !slices.Equal(issued.Credential.Scopes, before.Scopes) {
				t.Fatal("rotation changed stable credential metadata")
			}
		})
	}
}

func TestIssueRotateRejectBeforeStore(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(context.Context, *api.Service) (api.Issued, error)
	}{
		{name: "issue_invalid_ttl", call: func(ctx context.Context, s *api.Service) (api.Issued, error) {
			return s.Issue(ctx, api.IssueRequest{ClientID: testClientID, Name: adminContractName, TTL: 3 * time.Hour})
		}},
		{name: "issue_unknown_scope", call: func(ctx context.Context, s *api.Service) (api.Issued, error) {
			return s.Issue(ctx, api.IssueRequest{ClientID: testClientID, Name: adminContractName, Scopes: []string{"unknown"}})
		}},
		{name: "rotate_invalid_generation", call: func(ctx context.Context, s *api.Service) (api.Issued, error) {
			return s.Rotate(ctx, api.RotateRequest{CredentialID: adminContractCredentialID})
		}},
		{name: "rotate_invalid_grace", call: func(ctx context.Context, s *api.Service) (api.Issued, error) {
			return s.Rotate(ctx, api.RotateRequest{CredentialID: adminContractCredentialID, ExpectedGeneration: 3, GracePeriod: -1})
		}},
	} {
		for _, timed := range []bool{false, true} {
			t.Run(tc.name+adminStoreSuffix(timed), func(t *testing.T) {
				s, st, _ := newAdminContractService(t, timed)
				if _, err := tc.call(context.Background(), s); !errors.Is(err, api.ErrInvalid) {
					t.Fatalf("invalid request error=%v", err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := tc.call(ctx, s); !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled request error=%v", err)
				}
				if st.calls != 0 {
					t.Fatal("invalid or canceled request reached the store")
				}
			})
		}
	}
}

func adminStoreSuffix(timed bool) string {
	if timed {
		return "/timed"
	}
	return "/plain"
}

func TestIssueRotateStoreErrors(t *testing.T) {
	for _, timed := range []bool{false, true} {
		for _, storeErr := range []error{api.ErrConflict, errors.New("commit result unknown")} {
			for _, rotate := range []bool{false, true} {
				name := "issue"
				if rotate {
					name = "rotate"
				}
				t.Run(name+adminStoreSuffix(timed)+"/"+storeErr.Error(), func(t *testing.T) {
					checkAdminStoreError(t, timed, rotate, storeErr)
				})
			}
		}
	}
}

func checkAdminStoreError(t *testing.T, timed, rotate bool, storeErr error) {
	t.Helper()
	s, st, _ := newAdminContractService(t, timed)
	st.err = storeErr
	var issued api.Issued
	var err error
	if rotate {
		issued, err = s.Rotate(context.Background(), api.RotateRequest{
			CredentialID: adminContractCredentialID, ExpectedGeneration: 3,
		})
	} else {
		issued, err = s.Issue(context.Background(), api.IssueRequest{ClientID: testClientID, Name: adminContractName})
	}
	if !errors.Is(err, storeErr) || st.calls != 1 {
		t.Fatalf("store error=%v calls=%d", err, st.calls)
	}
	if issued.Token != "" || issued.Credential.ID != "" || !issued.ExpiresAt.IsZero() {
		t.Fatal("failed operation returned a partial issued secret")
	}
	changes, _ := s.TrackedChangesCount()
	if errors.Is(storeErr, api.ErrConflict) && changes != 0 {
		t.Fatal("definite rejection recorded an ambiguous write")
	}
	if !errors.Is(storeErr, api.ErrConflict) && changes == 0 {
		t.Fatal("ambiguous write did not invalidate affected identity")
	}
}
