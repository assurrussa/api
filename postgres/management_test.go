package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/postgres"
)

const managedReadScope = "read"

func TestManagementCardRetirement(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope, "write")); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "managed", managedReadScope, "write")
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientScopes(ctx, "a", []string{managedReadScope}); err != nil {
		t.Fatal(err)
	}
	next := v
	next.ID = "managed_v2"
	next.Generation = 2
	if _, err := s.Rotate(ctx, c.ID, 1, next, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	d, err := s.CredentialDetails(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Credential.Generation != 2 || d.CurrentVersion.ID != next.ID || d.UnexpiredVersions != 2 ||
		len(d.EffectiveScopes) != 1 || d.EffectiveScopes[0] != managedReadScope {
		t.Fatalf("incoherent card: %+v", d)
	}
	versions, err := s.SecretVersions(ctx, c.ID, 0, 1)
	if err != nil || len(versions) != 1 || versions[0].ID != next.ID {
		t.Fatalf("first page: %+v %v", versions, err)
	}
	versions, err = s.SecretVersions(ctx, c.ID, versions[0].Generation, 1)
	if err != nil || len(versions) != 1 || versions[0].ID != v.ID {
		t.Fatalf("next page: %+v %v", versions, err)
	}
	if err = s.RetireVersion(ctx, c.ID, next.ID); !errors.Is(err, api.ErrConflict) {
		t.Fatalf("current retirement: %v", err)
	}
	if err = s.RetireVersion(ctx, c.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	retired, err := s.Lookup(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RetireVersion(ctx, c.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Secret.ExpiresAt.Equal(retired.Secret.ExpiresAt) {
		t.Fatal("retirement extended previous deadline")
	}
	d, err = s.CredentialDetails(ctx, c.ID)
	if err != nil || d.UnexpiredVersions != 1 {
		t.Fatalf("retired card: %+v %v", d, err)
	}
}

func TestUsageMonotonicAfterPrune(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "usage-prune", managedReadScope)
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	next := v
	next.ID = "usage_v2"
	next.Generation = 2
	if _, err := s.Rotate(ctx, c.ID, 1, next, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	var err error
	observed := time.Now().UTC().Truncate(time.Microsecond)
	if err = s.RecordUsage(ctx, []api.UsageObservation{{
		ClientID: "a", CredentialID: c.ID, VersionID: v.ID, At: observed,
	}}); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordUsage(ctx, []api.UsageObservation{{
		ClientID: "a", CredentialID: c.ID, VersionID: v.ID, At: observed.Add(-time.Hour),
	}}); err != nil {
		t.Fatal(err)
	}
	versions, err := s.SecretVersions(ctx, c.ID, 2, 1)
	if err != nil || versions[0].LastUsedAt == nil || !versions[0].LastUsedAt.Equal(observed) {
		t.Fatalf("usage regressed: %+v %v", versions, err)
	}
	removed, err := s.PruneExpiredVersions(ctx, time.Now(), 10)
	if err != nil || removed != 1 {
		t.Fatalf("prune: %d %v", removed, err)
	}
	if err = s.RecordUsage(ctx, []api.UsageObservation{{
		ClientID: "a", CredentialID: c.ID, VersionID: v.ID, At: observed.Add(time.Hour),
	}}); err != nil {
		t.Fatal(err)
	}
	d, err := s.CredentialDetails(ctx, c.ID)
	if err != nil || d.LastUsedAt == nil || !d.LastUsedAt.Equal(observed) {
		t.Fatalf("credential usage lost or pruned usage revived: %+v %v", d, err)
	}
	if _, err = s.Lookup(ctx, v.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("pruned version recreated: %v", err)
	}
}

func repeatableReadStore(t *testing.T, ctx context.Context, s *postgres.Store) *postgres.Store {
	t.Helper()
	// Hosts can configure a stronger session default. Once must still re-read
	// the receipt after waiting for another caller's operation lock.
	config := s.Pool().Config()
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = string(pgx.RepeatableRead)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := postgres.New(pool, s.Schema())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestOnceConcurrentReplayAndRetention(t *testing.T) {
	s, ctx := testStore(t)
	s = repeatableReadStore(t, ctx, s)
	actor := api.Actor{Kind: "human", ID: "admin"}
	if err := s.CreateClientAudited(ctx, actor, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "once", managedReadScope)
	spec := api.OperationSpec{ID: "issue-once", Fingerprint: [32]byte{1}}
	type result struct {
		receipt api.OperationReceipt
		applied bool
		err     error
	}
	results := make(chan result, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, applied, err := s.IssueOnceAudited(ctx, actor, spec, c, v, time.Hour)
			results <- result{r, applied, err}
		})
	}
	wg.Wait()
	close(results)
	appliedCount := 0
	var receipt api.OperationReceipt
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.applied {
			appliedCount++
		}
		if r.receipt.Version.ID != v.ID || r.receipt.Fingerprint != spec.Fingerprint {
			t.Fatalf("bad receipt: %+v", r)
		}
		receipt = r.receipt
	}
	if appliedCount != 1 {
		t.Fatalf("applied %d times", appliedCount)
	}
	if err := s.SetClientBanned(ctx, "a", true); err != nil {
		t.Fatal(err)
	}
	replay, applied, err := s.IssueOnceAudited(ctx, actor, spec, api.Credential{}, api.SecretVersion{}, -time.Second)
	if err != nil || applied || !replay.CommittedAt.Equal(receipt.CommittedAt) {
		t.Fatalf("replay checked current policy: %+v %t %v", replay, applied, err)
	}
	changed := spec
	changed.Fingerprint[0] = 2
	if _, _, err = s.IssueOnceAudited(ctx, actor, changed, c, v, time.Hour); !errors.Is(err, api.ErrConflict) {
		t.Fatalf("changed fingerprint: %v", err)
	}
	events, err := s.AuditEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].OperationID != spec.ID {
		t.Fatalf("replay duplicated audit: %+v", events)
	}
	page, err := s.AuditEvents(ctx, events[0].ID, 1)
	if err != nil || len(page) != 1 || page[0].ID != events[1].ID {
		t.Fatalf("audit cursor: %+v %v", page, err)
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "digest") || strings.Contains(string(body), "token") ||
		strings.Contains(string(body), "fingerprint") {
		t.Fatalf("sensitive receipt: %s", body)
	}
	if removed, err := s.PruneAuditEvents(ctx, time.Now(), 10); err != nil || removed != 2 {
		t.Fatalf("audit prune: %d %v", removed, err)
	}
	saved, err := s.Operation(ctx, spec.ID)
	if err != nil || saved.Fingerprint != spec.Fingerprint || saved.Version.ID != v.ID {
		t.Fatalf("receipt lost after audit prune: %+v %v", saved, err)
	}
}

func TestAuditFailureRollsBackMutationAndReceipt(t *testing.T) {
	s, ctx := testStore(t)
	actor := api.Actor{Kind: "service", ID: "operator"}
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	query := `ALTER TABLE ` + s.Table("audit_events") + ` ADD CONSTRAINT reject_issue CHECK (action <> 'credential.issue')`
	_, err := s.Pool().Exec(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "rollback", managedReadScope)
	spec := api.OperationSpec{ID: "rollback-op", Fingerprint: [32]byte{2}}
	if _, _, err = s.IssueOnceAudited(ctx, actor, spec, c, v, time.Hour); err == nil {
		t.Fatal("audit insertion unexpectedly succeeded")
	}
	if _, err = s.Credential(ctx, c.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("mutation survived audit error: %v", err)
	}
	if _, err = s.Operation(ctx, spec.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("receipt survived audit error: %v", err)
	}
	if err = s.IssueAudited(ctx, api.Actor{}, c, v); !errors.Is(err, api.ErrInvalid) {
		t.Fatalf("missing actor: %v", err)
	}
}

func TestConcurrentRotateOnce(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "rotate-once", managedReadScope)
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	spec := api.OperationSpec{ID: "rotate-op", Fingerprint: [32]byte{3}}
	type result struct {
		r       api.OperationReceipt
		applied bool
		err     error
	}
	out := make(chan result, 4)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			next := v
			next.ID = fmt.Sprintf("rotated_%d", i)
			next.Generation = 2
			r, applied, err := s.RotateOnce(ctx, spec, c.ID, 1, next, time.Hour, 0)
			out <- result{r, applied, err}
		})
	}
	wg.Wait()
	close(out)
	appliedCount := 0
	versionID := ""
	for got := range out {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.applied {
			appliedCount++
		}
		if versionID == "" {
			versionID = got.r.Version.ID
		}
		if got.r.Version.ID != versionID || got.r.Credential.Generation != 2 {
			t.Fatalf("different replay: %+v", got)
		}
	}
	if appliedCount != 1 {
		t.Fatalf("rotated %d times", appliedCount)
	}
	if removed, err := s.PruneExpiredVersions(ctx, time.Now(), 10); err != nil || removed != 1 {
		t.Fatalf("prune old version: %d %v", removed, err)
	}
	if _, applied, err := s.RotateOnce(ctx, spec, c.ID, 1, api.SecretVersion{}, -1, -1); err != nil || applied {
		t.Fatalf("post-prune replay: %t %v", applied, err)
	}
}

func TestUsageDoesNotNotify(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "usage-notify", managedReadScope)
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	listener, err := s.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Release()
	if _, err = listener.Exec(ctx, `LISTEN `+pgx.Identifier{s.Channel()}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordUsage(ctx, []api.UsageObservation{{
		ClientID: "a", CredentialID: c.ID, VersionID: v.ID, At: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if notification, err := listener.Conn().WaitForNotification(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("usage emitted invalidation: %+v %v", notification, err)
	}
}

func TestAuditedCommandsRecordSafeCommittedResults(t *testing.T) {
	s, ctx := testStore(t)
	actor := api.Actor{Kind: "service", ID: "control-plane"}
	if err := s.CreateClientAudited(ctx, actor, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientScopesAudited(ctx, actor, "a", []string{managedReadScope}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientBannedAudited(ctx, actor, "a", false); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "audited", managedReadScope)
	if err := s.IssueAudited(ctx, actor, c, v); err != nil {
		t.Fatal(err)
	}
	next := v
	next.ID = "audited_v2"
	next.Generation = 2
	if _, err := s.RotateAudited(ctx, actor, c.ID, 1, next, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAudited(ctx, actor, c.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	timed, initial := grant("a", "audited-timed", managedReadScope)
	timed, initial, err := s.IssueWithLifetimeAudited(ctx, actor, timed, initial, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next = initial
	next.ID = "audited_timed_v2"
	next.Generation = 2
	if _, _, err = s.RotateWithLifetimeAudited(ctx, actor, timed.ID, 1, next, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = s.RetireVersionAudited(ctx, actor, timed.ID, initial.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeAllAudited(ctx, actor, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	events, err := s.AuditEvents(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 10 {
		t.Fatalf("got %d events for10 audited commands", len(events))
	}
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.Action]++
		if event.Actor != actor || event.ClientID != "a" {
			t.Fatalf("wrong actor/ownership: %+v", event)
		}
		if event.Action == "credential.rotate" || event.Action == "credential.issue" {
			if event.Details["generation"] == nil || event.Details["expires_at"] == nil || event.Details["scopes"] == nil {
				t.Fatalf("missing safe result metadata: %+v", event)
			}
		}
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "digest") || strings.Contains(string(body), "token") {
			t.Fatalf("sensitive audit: %s", body)
		}
	}
	if counts["credential.issue"] != 2 || counts["credential.rotate"] != 2 || counts["version.retire"] != 1 {
		t.Fatalf("missing command audit: %+v", counts)
	}
}

func TestReceiptSurvivesPruningItsSecretVersion(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "pruned-receipt", managedReadScope)
	spec := api.OperationSpec{ID: "retained-issue", Fingerprint: [32]byte{5}}
	original, applied, err := s.IssueOnce(ctx, spec, c, v, time.Hour)
	if err != nil || !applied {
		t.Fatalf("initial operation: %t %v", applied, err)
	}
	next := v
	next.ID = "retained_v2"
	next.Generation = 2
	if _, err = s.Rotate(ctx, c.ID, 1, next, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.PruneExpiredVersions(ctx, time.Now(), 10); err != nil || removed != 1 {
		t.Fatalf("prune: %d %v", removed, err)
	}
	if _, err = s.Lookup(ctx, v.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("version retained: %v", err)
	}
	receipt, err := s.Operation(ctx, spec.ID)
	if err != nil || receipt.Version.ID != v.ID || !receipt.CommittedAt.Equal(original.CommittedAt) {
		t.Fatalf("receipt lost: %+v %v", receipt, err)
	}
	replay, applied, err := s.IssueOnce(ctx, spec, api.Credential{}, api.SecretVersion{}, 0)
	if err != nil || applied || replay.Version.ID != v.ID {
		t.Fatalf("pruned version replay: %+v %t %v", replay, applied, err)
	}
}
