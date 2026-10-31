package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/postgres"
)

func namedManagementStore(t *testing.T, ctx context.Context, s *postgres.Store, name string) *postgres.Store {
	t.Helper()
	config := s.Pool().Config()
	config.ConnConfig.RuntimeParams["application_name"] = name
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

func waitManagementBlocked(t *testing.T, ctx context.Context, s *postgres.Store, application string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := s.Pool().QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, application).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s never reached the database lock barrier: %v", application, ctx.Err())
		case <-ticker.C:
		}
	}
}

func lockManagementClient(t *testing.T, ctx context.Context, s *postgres.Store, id string) pgx.Tx {
	t.Helper()
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id FROM `+s.Table("clients")+` WHERE id=$1 FOR UPDATE`, id).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	return tx
}

func assertManagementSnapshot(t *testing.T, d api.CredentialDetails, base time.Time) {
	t.Helper()
	generation := d.Credential.Generation
	wantScope := managedReadScope
	if generation%2 == 0 {
		wantScope = "write"
	}
	wantVersion := fmt.Sprintf("snapshot_v%d", generation)
	if generation < 1 || d.CurrentVersion.Generation != generation || d.CurrentVersion.ID != wantVersion ||
		d.CurrentVersion.CredentialID != d.Credential.ID || int64(d.UnexpiredVersions) != generation ||
		!d.CurrentVersion.ExpiresAt.Equal(base.Add(time.Duration(generation)*time.Hour)) ||
		!slices.Equal(d.EffectiveScopes, []string{wantScope}) {
		t.Errorf("card mixed committed rotation/policy states: %+v", d)
	}
}

func rotateManagementSnapshots(ctx context.Context, writer *postgres.Store, v api.SecretVersion,
	base time.Time, published chan<- int64, observed <-chan struct{},
) error {
	for generation := int64(2); generation <= 32; generation++ {
		next := v
		next.ID = fmt.Sprintf("snapshot_v%d", generation)
		next.Generation = generation
		next.ExpiresAt = base.Add(time.Duration(generation) * time.Hour)
		if _, err := writer.Rotate(ctx, v.CredentialID, generation-1, next, 48*time.Hour, base); err != nil {
			return err
		}
		select {
		case published <- generation:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-observed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestCredentialDetailsConcurrentRotationPolicySnapshot(t *testing.T) {
	s, parent := testStore(t)
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if err := s.CreateClient(ctx, client("a", managedReadScope, "write")); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "snapshot", managedReadScope, "write")
	base := time.Now().UTC().Truncate(time.Microsecond)
	v.ExpiresAt = base.Add(time.Hour)
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientScopes(ctx, "a", []string{managedReadScope}); err != nil {
		t.Fatal(err)
	}
	// Publish policy in the same transaction as each real Store.Rotate call.
	// Every committed state has one unique generation/scope/expiry/count tuple.
	query := `CREATE FUNCTION ` + s.QuotedSchema() + `.snapshot_policy() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 UPDATE ` + s.Table("clients") + ` SET scopes=ARRAY[CASE WHEN NEW.generation % 2=0 THEN 'write' ELSE 'read' END]
 WHERE id=NEW.client_id;
 RETURN NEW;
 END $$;
 CREATE TRIGGER snapshot_policy AFTER UPDATE OF generation ON ` + s.Table("credentials") + `
 FOR EACH ROW EXECUTE FUNCTION ` + s.QuotedSchema() + `.snapshot_policy()`
	if _, err := s.Pool().Exec(ctx, query); err != nil {
		t.Fatal(err)
	}
	application := s.Schema() + "_rotate"
	writer := namedManagementStore(t, ctx, s, application)
	barrier := lockManagementClient(t, ctx, s, "a")
	rotated := make(chan error, 1)
	published := make(chan int64)
	observed := make(chan struct{})
	go func() {
		defer close(published)
		rotated <- rotateManagementSnapshots(ctx, writer, v, base, published, observed)
	}()
	waitManagementBlocked(t, ctx, s, application)
	before, err := s.CredentialDetails(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertManagementSnapshot(t, before, base)
	if before.Credential.Generation != 1 {
		t.Fatal("rotation escaped the client lock barrier")
	}
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 80 {
				d, readErr := s.CredentialDetails(ctx, c.ID)
				if readErr != nil {
					t.Error(readErr)
					return
				}
				assertManagementSnapshot(t, d, base)
			}
		})
	}
	if err = barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Require a card read of every published generation before the next
	// rotation starts; the independent readers keep loading the read path.
	observedGeneration := int64(1)
	for generation := range published {
		d, readErr := s.CredentialDetails(ctx, c.ID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		assertManagementSnapshot(t, d, base)
		if generation != observedGeneration+1 || d.Credential.Generation != generation {
			t.Fatalf("published generation %d after %d, read %d", generation, observedGeneration, d.Credential.Generation)
		}
		observedGeneration = generation
		select {
		case observed <- struct{}{}:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err = <-rotated; err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	after, err := s.CredentialDetails(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertManagementSnapshot(t, after, base)
	if after.Credential.Generation != 32 || observedGeneration != 32 {
		t.Fatalf("rotations stopped at generation %d, last observed %d", after.Credential.Generation, observedGeneration)
	}
}

func TestCredentialDetailsExpiredCurrentWithLiveGraceVersion(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, previous := grant("a", "expired-current", managedReadScope)
	if err := s.Issue(ctx, c, previous); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	current := previous
	current.ID = "expired-current_v2"
	current.Generation = 2
	current.CreatedAt = at
	current.ExpiresAt = at.Add(time.Second)
	if _, err := s.Rotate(ctx, c.ID, 1, current, time.Hour, at); err != nil {
		t.Fatal(err)
	}
	d, err := s.CredentialDetails(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Credential.Generation != 2 || d.CurrentVersion.ID != current.ID || d.CurrentVersion.Generation != 2 ||
		!d.CurrentVersion.ExpiresAt.Equal(current.ExpiresAt) || !d.CurrentVersion.CreatedAt.Equal(at) ||
		d.UnexpiredVersions != 1 || !slices.Equal(d.EffectiveScopes, []string{managedReadScope}) {
		t.Fatalf("expired current version hid or replaced valid grace metadata: %+v", d)
	}
	old, err := s.Lookup(ctx, previous.ID)
	if err != nil || !old.Secret.ExpiresAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("historical grace version was not retained: %+v %v", old, err)
	}
}

func assertManagementUsage(t *testing.T, ctx context.Context, s *postgres.Store, c api.Credential, v api.SecretVersion,
	want time.Time,
) {
	t.Helper()
	d, err := s.CredentialDetails(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := s.SecretVersions(ctx, c.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d.LastUsedAt == nil || !d.LastUsedAt.Equal(want) {
		t.Fatalf("credential usage regressed: %+v; want %s", d.LastUsedAt, want)
	}
	for _, version := range versions {
		if version.ID == v.ID {
			if version.LastUsedAt == nil || !version.LastUsedAt.Equal(want) {
				t.Fatalf("version usage regressed: %+v; want %s", version, want)
			}
			return
		}
	}
	t.Fatalf("usage version %s missing", v.ID)
}

func TestRecordUsageConcurrentOppositeBatches(t *testing.T) {
	s, parent := testStore(t)
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	credentials := make([]api.Credential, 0, 2)
	versions := make([]api.SecretVersion, 0, 2)
	for _, id := range []string{"a", "b"} {
		if err := s.CreateClient(ctx, client(id, managedReadScope)); err != nil {
			t.Fatal(err)
		}
		c, v := grant(id, "usage-"+id, managedReadScope)
		if err := s.Issue(ctx, c, v); err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, c)
		versions = append(versions, v)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	low := make([]api.UsageObservation, 0, len(credentials))
	for i, c := range credentials {
		low = append(low, api.UsageObservation{
			ClientID: c.ClientID, CredentialID: c.ID, VersionID: versions[i].ID, At: observed,
		})
	}
	high := slices.Clone(low)
	slices.Reverse(high)
	for i := range high {
		high[i].At = observed.Add(time.Hour)
	}
	barrier := lockManagementClient(t, ctx, s, "a")
	results := make(chan error, 2)
	for i, batch := range [][]api.UsageObservation{low, high} {
		application := fmt.Sprintf("%s_usage_%d", s.Schema(), i)
		writer := namedManagementStore(t, ctx, s, application)
		go func() { results <- writer.RecordUsage(ctx, batch) }()
		waitManagementBlocked(t, ctx, s, application)
	}
	if err := barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent opposite-order batches failed: %v", err)
		}
	}
	if err := s.RecordUsage(ctx, low); err != nil {
		t.Fatal(err)
	}
	for i, c := range credentials {
		assertManagementUsage(t, ctx, s, c, versions[i], observed.Add(time.Hour))
	}
}

func TestRecordUsageOverlapsPruneWithoutResurrection(t *testing.T) {
	s, parent := testStore(t)
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if err := s.CreateClient(ctx, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, old := grant("a", "overlap-prune", managedReadScope)
	if err := s.Issue(ctx, c, old); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	observation := api.UsageObservation{ClientID: c.ClientID, CredentialID: c.ID, VersionID: old.ID, At: observed}
	if err := s.RecordUsage(ctx, []api.UsageObservation{observation}); err != nil {
		t.Fatal(err)
	}
	next := old
	next.ID = "overlap-prune_v2"
	next.Generation = 2
	if _, err := s.Rotate(ctx, c.ID, 1, next, 0, observed.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	barrier := lockManagementClient(t, ctx, s, c.ClientID)
	application := s.Schema() + "_prune_usage"
	writer := namedManagementStore(t, ctx, s, application)
	usage := make(chan error, 1)
	observation.At = observed.Add(time.Hour)
	go func() { usage <- writer.RecordUsage(ctx, []api.UsageObservation{observation}) }()
	waitManagementBlocked(t, ctx, s, application)
	// RecordUsage is demonstrably in flight while pruning commits the deletion.
	removed, err := s.PruneExpiredVersions(ctx, observed, 10)
	if err != nil || removed != 1 {
		t.Fatalf("overlapping prune: removed %d: %v", removed, err)
	}
	if err = barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-usage; err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lookup(ctx, old.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("in-flight usage resurrected a deleted version: %v", err)
	}
	d, err := s.CredentialDetails(ctx, c.ID)
	if err != nil || d.LastUsedAt == nil || !d.LastUsedAt.Equal(observed) ||
		d.CurrentVersion.ID != next.ID || d.CurrentVersion.LastUsedAt != nil {
		t.Fatalf("pruning lost stable usage or attributed deleted usage to current version: %+v %v", d, err)
	}
}

func TestManagementCursorLimitBounds(t *testing.T) {
	s, ctx := testStore(t)
	actor := api.Actor{Kind: "human", ID: "pagination"}
	if err := s.CreateClientAudited(ctx, actor, client("a", managedReadScope)); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", "page-bounds", managedReadScope)
	if err := s.IssueAudited(ctx, actor, c, v); err != nil {
		t.Fatal(err)
	}
	next := v
	next.ID = "page-bounds_v2"
	next.Generation = 2
	if _, err := s.RotateAudited(ctx, actor, c.ID, 1, next, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 1001} {
		if _, err := s.SecretVersions(ctx, c.ID, 0, limit); !errors.Is(err, api.ErrInvalid) {
			t.Errorf("SecretVersions limit %d: %v", limit, err)
		}
		if _, err := s.AuditEvents(ctx, 0, limit); !errors.Is(err, api.ErrInvalid) {
			t.Errorf("AuditEvents limit %d: %v", limit, err)
		}
	}
	if _, err := s.SecretVersions(ctx, c.ID, -1, 1); !errors.Is(err, api.ErrInvalid) {
		t.Errorf("SecretVersions negative cursor: %v", err)
	}
	if _, err := s.AuditEvents(ctx, -1, 1); !errors.Is(err, api.ErrInvalid) {
		t.Errorf("AuditEvents negative cursor: %v", err)
	}
	for _, limit := range []int{1, 1000} {
		t.Run(fmt.Sprintf("limit_%d", limit), func(t *testing.T) {
			versions, err := s.SecretVersions(ctx, c.ID, 0, limit)
			if err != nil || len(versions) != min(limit, 2) || versions[0].ID != next.ID {
				t.Fatalf("version page: %+v %v", versions, err)
			}
			older, err := s.SecretVersions(ctx, c.ID, next.Generation, limit)
			if err != nil || len(older) != 1 || older[0].ID != v.ID {
				t.Fatalf("exclusive generation cursor: %+v %v", older, err)
			}
			events, err := s.AuditEvents(ctx, 0, limit)
			if err != nil || len(events) != min(limit, 3) || events[0].Action != "credential.rotate" {
				t.Fatalf("audit page: %+v %v", events, err)
			}
			page, err := s.AuditEvents(ctx, events[0].ID, limit)
			if err != nil || len(page) != min(limit, 2) || page[0].Action != "credential.issue" ||
				page[0].ID >= events[0].ID {
				t.Fatalf("exclusive event cursor: %+v %v", page, err)
			}
		})
	}
}
