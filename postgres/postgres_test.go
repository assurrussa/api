package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/postgres"
)

func testStore(t *testing.T) (*postgres.Store, context.Context) {
	t.Helper()
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("API_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	schema := fmt.Sprintf("api_test_%d", time.Now().UnixNano())
	s, err := postgres.New(pool, schema)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+s.QuotedSchema()+` CASCADE`) })
	return s, ctx
}

func client(id string, scopes ...string) api.Client {
	return api.Client{ID: id, Name: id, Scopes: scopes, CreatedAt: time.Now().UTC()}
}

func grant(clientID, id string, scopes ...string) (api.Credential, api.SecretVersion) {
	now := time.Now().UTC()
	c := api.Credential{ID: id, ClientID: clientID, Name: id, Scopes: scopes, Generation: 1, CreatedAt: now}
	v := api.SecretVersion{ID: id + "_v1", CredentialID: id, Generation: 1, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	v.Digest[0] = 1
	return c, v
}

const testKey = "key"

func TestAuthorityAndIsolation(t *testing.T) {
	s, ctx := testStore(t)
	otherSchema := s.Schema() + "_other"
	other, err := postgres.New(s.Pool(), otherSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.Pool().Exec(context.Background(), `DROP SCHEMA `+other.QuotedSchema()+` CASCADE`) })
	if err = s.CreateClient(ctx, client("a", "read", "write")); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Client(ctx, "a"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("schema leaked: %v", err)
	}
	c, v := grant("a", testKey, "read")
	if err = s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	r, err := s.Lookup(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Client.ID != "a" || r.Credential.ID != testKey || r.Secret.Digest != v.Digest {
		t.Fatalf("bad joined record: %+v", r)
	}
	if _, err = other.Lookup(ctx, v.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("version leaked: %v", err)
	}
	if err = s.SetClientScopes(ctx, "a", []string{"read"}); err != nil {
		t.Fatal(err)
	}
	rot := api.SecretVersion{
		ID:           "key_v2",
		CredentialID: testKey,
		Generation:   2,
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	if _, err = s.Rotate(ctx, testKey, 1, rot, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	old, err := s.Lookup(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Secret.ExpiresAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("old secret not retired: %v", old.Secret.ExpiresAt)
	}
	if err = s.SetClientBanned(ctx, "a", true); err != nil {
		t.Fatal(err)
	}
	bad, badV := grant("a", "bad", "read")
	if err = s.Issue(ctx, bad, badV); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("banned issue: %v", err)
	}
	if _, err = s.Lookup(ctx, badV.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("partial issue: %v", err)
	}
	v3 := api.SecretVersion{
		ID:           "key_v3",
		CredentialID: testKey,
		Generation:   3,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if _, err = s.Rotate(ctx, testKey, 2, v3, 0, time.Now()); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("banned rotate: %v", err)
	}
	if err = s.RevokeAll(ctx, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Credential(ctx, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Fatal("revoke all did not revoke")
	}
}

func TestConcurrentRotateAndRejectedWrites(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", "read")); err != nil {
		t.Fatal(err)
	}
	c, v := grant("a", testKey, "read")
	if err := s.Issue(ctx, c, v); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next := api.SecretVersion{
				ID:           fmt.Sprintf("v2_%d", i),
				CredentialID: testKey,
				Generation:   2,
				ExpiresAt:    time.Now().Add(time.Hour),
				CreatedAt:    time.Now(),
			}
			_, err := s.Rotate(ctx, testKey, 1, next, time.Minute, time.Now())
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, api.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("rotate outcomes: success=%d conflicts=%d", success, conflicts)
	}
	var versions int
	countSQL := `SELECT count(*) FROM ` + s.Table("secret_versions") + ` WHERE credential_id='key'`
	if err := s.Pool().QueryRow(ctx, countSQL).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("versions=%d", versions)
	}
	denied, deniedV := grant("a", "denied", "admin")
	if err := s.Issue(ctx, denied, deniedV); !errors.Is(err, api.ErrForbidden) {
		t.Fatalf("scope check: %v", err)
	}
	if _, err := s.Credential(ctx, "denied"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("partial rejected issue: %v", err)
	}
}

func TestWatchCommittedChanges(t *testing.T) {
	s, ctx := testStore(t)
	watchCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	events := make(chan struct{}, 10)
	done := make(chan error, 1)
	go func() { done <- s.Watch(watchCtx, func() { events <- struct{}{} }) }()
	select {
	case <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("initial invalidate missing")
	}
	if err := s.CreateClient(ctx, client("a", "read")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("mutation notification missing")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not stop")
	}
}

type rollbackProbe struct {
	pgx.Tx
	deadline time.Time
}

func (p *rollbackProbe) Rollback(ctx context.Context) error {
	var ok bool
	p.deadline, ok = ctx.Deadline()
	if !ok {
		return errors.New("rollback has no deadline")
	}
	return nil
}

func TestRollbackHasIndependentDeadline(t *testing.T) {
	p := &rollbackProbe{}
	postgres.Rollback(p)
	remaining := time.Until(p.deadline)
	if remaining <= 0 || remaining > postgres.RollbackTimeout {
		t.Fatalf("rollback deadline remaining: %v", remaining)
	}
}

func TestTimedIssueStartsLifetimeAfterLockWait(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("timed", "read")); err != nil {
		t.Fatal(err)
	}
	lock, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(ctx, `SELECT id FROM `+s.Table("clients")+` WHERE id='timed' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	c, v := grant("timed", "short", "read")
	type result struct {
		c   api.Credential
		v   api.SecretVersion
		err error
	}
	done := make(chan result, 1)
	go func() { c, v, err := s.IssueWithLifetime(ctx, c, v, time.Second); done <- result{c, v, err} }()
	select {
	case r := <-done:
		t.Fatalf("issue completed before lock release: %+v", r)
	case <-time.After(1200 * time.Millisecond):
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if remaining := time.Until(r.v.ExpiresAt); remaining < 500*time.Millisecond {
			t.Fatalf("new token already nearly expired: %v", remaining)
		}
		if r.c.CreatedAt != r.v.CreatedAt {
			t.Fatalf("credential/version times differ: %v %v", r.c.CreatedAt, r.v.CreatedAt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("issue did not finish")
	}
}

func TestTimedRotateStartsGraceAfterLockWait(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("timed_rotate", "read")); err != nil {
		t.Fatal(err)
	}
	c, old := grant("timed_rotate", "rotating", "read")
	if err := s.Issue(ctx, c, old); err != nil {
		t.Fatal(err)
	}
	lock, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(ctx, `SELECT id FROM `+s.Table("clients")+` WHERE id='timed_rotate' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	next := api.SecretVersion{
		ID:           "rotating_v2",
		CredentialID: c.ID,
		Generation:   2,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	done := make(chan error, 1)
	go func() { _, _, err := s.RotateWithLifetime(ctx, c.ID, 1, next, time.Hour, time.Second); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("rotation completed before lock release: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotate did not finish")
	}
	oldRecord, err := s.Lookup(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(oldRecord.Secret.ExpiresAt); remaining < 500*time.Millisecond {
		t.Fatalf("grace already nearly spent: %v", remaining)
	}
}

func TestPruneExpiredVersionsKeepsCurrentAndAllowsRotation(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("prune", "read")); err != nil {
		t.Fatal(err)
	}
	c, v1 := grant("prune", "history", "read")
	v1.ExpiresAt = time.Now().Add(-48 * time.Hour)
	if err := s.Issue(ctx, c, v1); err != nil {
		t.Fatal(err)
	}
	v2 := api.SecretVersion{
		ID:           "history_v2",
		CredentialID: c.ID,
		Generation:   2,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(-24 * time.Hour),
	}
	if _, err := s.Rotate(ctx, c.ID, 1, v2, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	v3 := api.SecretVersion{
		ID:           "history_v3",
		CredentialID: c.ID,
		Generation:   3,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if _, err := s.Rotate(ctx, c.ID, 2, v3, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		removed, err := s.PruneExpiredVersions(ctx, time.Now().Add(-time.Hour), 1)
		if err != nil || removed != 1 {
			t.Fatalf("batch %d: removed=%d err=%v", i, removed, err)
		}
	}
	if _, err := s.Lookup(ctx, v1.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("old version retained: %v", err)
	}
	if _, err := s.Lookup(ctx, v3.ID); err != nil {
		t.Fatalf("current version removed: %v", err)
	}
	v4 := api.SecretVersion{
		ID:           "history_v4",
		CredentialID: c.ID,
		Generation:   4,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if _, err := s.Rotate(ctx, c.ID, 3, v4, 0, time.Now()); err != nil {
		t.Fatalf("rotation after prune: %v", err)
	}
}

func TestWatchReportsRecoverableErrors(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://127.0.0.1:1/test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.BeforeConnect = func(context.Context, *pgx.ConnConfig) error { return errors.New("listener hook unavailable") }
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := postgres.New(pool, "watch_errors")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reported := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.WatchWithErrors(ctx, func() {}, func(err error) {
			select {
			case reported <- err:
			default:
			}
		})
	}()
	select {
	case err := <-reported:
		if err == nil {
			t.Fatal("nil listener failure")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failure was not reported")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not stop")
	}
}

func TestWatchUsesPoolConnectionHooks(t *testing.T) {
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("API_TEST_DATABASE_URL required")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	password := cfg.ConnConfig.Password
	cfg.ConnConfig.Password = ""
	var before, after atomic.Int32
	cfg.BeforeConnect = func(_ context.Context, conn *pgx.ConnConfig) error {
		before.Add(1)
		conn.Password = password
		return nil
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		after.Add(1)
		_, err := conn.Exec(ctx, "SET application_name='api_watch_hook_test'")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := postgres.New(pool, "watch_hooks")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.Watch(ctx, func() {
			select {
			case ready <- struct{}{}:
			default:
			}
		})
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not connect")
	}
	if before.Load() == 0 || after.Load() == 0 {
		t.Fatalf("pool hooks skipped: before=%d after=%d", before.Load(), after.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
}

func TestWatchReconnectAfterListenerTermination(t *testing.T) {
	s, ctx := testStore(t)
	config, err := pgxpool.ParseConfig(os.Getenv("API_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	appName := fmt.Sprintf("api_watch_%d", time.Now().UnixNano())
	config.ConnConfig.RuntimeParams["application_name"] = appName
	attempts := make(chan time.Time, 10)
	const initialDialFailures = 3
	var attempt int
	config.BeforeConnect = func(_ context.Context, conn *pgx.ConnConfig) error {
		attempts <- time.Now()
		attempt++
		if attempt <= initialDialFailures {
			conn.DialFunc = func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("listener dial unavailable")
			}
		}
		return nil
	}
	listenerPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listenerPool.Close)
	listener, err := postgres.New(listenerPool, s.Schema())
	if err != nil {
		t.Fatal(err)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	events := make(chan struct{}, 10)
	failures := make(chan time.Time, 10)
	done := make(chan error, 1)
	go func() {
		done <- listener.WatchWithErrors(watchCtx, func() { events <- struct{}{} }, func(error) {
			failures <- time.Now()
		})
	}()
	waitEvent := func(phase string) {
		t.Helper()
		select {
		case <-events:
		case err := <-done:
			t.Fatalf("watch stopped during %s: %v", phase, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("no invalidate during %s", phase)
		}
	}
	waitEvent("initial subscription")
	for range initialDialFailures + 1 {
		waitWatchTime(t, attempts)
	}
	for range initialDialFailures {
		waitWatchTime(t, failures)
	}

	// Match both the unique test application and the exact LISTEN statement.
	// The admin query runs through s.pool, never through listenerPool.
	listenQuery := `LISTEN ` + `"` + listener.Channel() + `"`
	listenerPID := func() int32 {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		query := `SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND query=$2 AND state='idle'`
		for time.Now().Before(deadline) {
			var pid int32
			err := s.Pool().QueryRow(ctx, query, appName, listenQuery).Scan(&pid)
			if err == nil {
				return pid
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal(err)
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("dedicated listener backend was not found")
		return 0
	}
	termQuery := `SELECT pg_terminate_backend(pid) FROM pg_stat_activity ` +
		`WHERE pid=$1 AND application_name=$2 AND query=$3 AND state='idle'`
	for reconnect := range 4 {
		oldPID := listenerPID()
		var terminated bool
		if err := s.Pool().QueryRow(ctx, termQuery, oldPID, appName, listenQuery).Scan(&terminated); err != nil {
			t.Fatal(err)
		}
		if !terminated {
			t.Fatal("dedicated listener backend was not terminated")
		}
		failedAt := waitWatchTime(t, failures)
		attemptedAt := waitWatchTime(t, attempts)
		// Measure only the retry wait, excluding PostgreSQL connection latency.
		// The margin tolerates scheduling delays but catches the fourth 800ms retry.
		delay := attemptedAt.Sub(failedAt)
		t.Logf("reconnect %d retry wait: %v", reconnect+1, delay)
		if delay > 500*time.Millisecond {
			t.Fatalf("successful LISTEN did not reset retry backoff: reconnect=%d delay=%v", reconnect+1, delay)
		}
		waitEvent("reconnection")
		if newPID := listenerPID(); newPID == oldPID {
			t.Fatal("listener did not reconnect to a new backend")
		}
	}

	if err := s.CreateClient(ctx, client("after_reconnect", "read")); err != nil {
		t.Fatal(err)
	}
	waitEvent("notification after reconnection")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop after cancellation")
	}
}

func TestRevokeAllAndIssueSerialize(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", "read")); err != nil {
		t.Fatal(err)
	}
	before, beforeVersion := grant("a", "before", "read")
	if err := s.Issue(ctx, before, beforeVersion); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	const count = 20
	var wg sync.WaitGroup
	errorsCh := make(chan error, count+1)
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, v := grant("a", fmt.Sprintf("key_%d", i), "read")
			errorsCh <- s.Issue(ctx, c, v)
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); errorsCh <- s.RevokeAll(ctx, "a", time.Now()) }()
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	after, afterVersion := grant("a", "after", "read")
	if err := s.Issue(ctx, after, afterVersion); err != nil {
		t.Fatal(err)
	}
	creds, err := s.Credentials(ctx, "a", "", count+2)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != count+2 {
		t.Fatalf("credentials=%d, want %d", len(creds), count+2)
	}
	byID := make(map[string]api.Credential, len(creds))
	for _, credential := range creds {
		byID[credential.ID] = credential
	}
	if byID[before.ID].RevokedAt == nil {
		t.Fatal("credential committed before RevokeAll remained active")
	}
	if byID[after.ID].RevokedAt != nil {
		t.Fatal("credential committed after RevokeAll was revoked")
	}
}

func TestRevokeAllWaitsForInFlightIssueCommit(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("a", "read")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The trigger pauses Issue after it has locked the client but before its
	// credential insert commits. RevokeAll must wait for that same client lock.
	key := time.Now().UnixNano()
	blocker, err := s.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		}
	}()
	if _, err := s.Pool().Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.block_issue() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_advisory_xact_lock(%d); RETURN NEW; END $$`, s.QuotedSchema(), key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `CREATE TRIGGER block_issue AFTER INSERT ON `+s.Table("credentials")+
		` FOR EACH ROW EXECUTE FUNCTION `+s.QuotedSchema()+`.block_issue()`); err != nil {
		t.Fatal(err)
	}
	waitForLock := func(fragment string) {
		t.Helper()
		for {
			var blocked int
			err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE pid <> pg_backend_pid() AND wait_event_type='Lock' AND position($1 in query)>0`, fragment).Scan(&blocked)
			if err != nil {
				t.Fatal(err)
			}
			if blocked > 0 {
				return
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("query did not block (%s): %v", fragment, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	c, v := grant("a", "in_flight", "read")
	issued := make(chan error, 1)
	go func() { issued <- s.Issue(ctx, c, v) }()
	waitForLock(`INSERT INTO ` + s.Table("credentials"))
	revoked := make(chan error, 1)
	go func() { revoked <- s.RevokeAll(ctx, "a", time.Now()) }()
	waitForLock(`FROM ` + s.Table("clients") + ` WHERE id=$1 FOR UPDATE`)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
		t.Fatal(err)
	}
	locked = false
	if err := <-issued; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	got, err := s.Credential(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Fatal("RevokeAll missed the issue committed while it waited for the client lock")
	}
}
