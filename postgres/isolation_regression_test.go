package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api/postgres"
)

func testStoreAtIsolation(t *testing.T, isolation string, migrate bool) (*postgres.Store, context.Context) {
	t.Helper()
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("API_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	schema := fmt.Sprintf("api_isolation_%d", time.Now().UnixNano())
	s, err := postgres.New(pool, schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+s.QuotedSchema()+` CASCADE`) })
	var actual string
	if err := pool.QueryRow(ctx, `SHOW default_transaction_isolation`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != isolation {
		t.Fatalf("default isolation=%q, want %q", actual, isolation)
	}
	t.Logf("connection default_transaction_isolation=%s", actual)
	if migrate {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return s, ctx
}

func waitForIsolationLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fragment string) {
	t.Helper()
	for {
		var blocked int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
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
		time.Sleep(time.Millisecond)
	}
}

func TestMigrateWaitsForInFlightMigration(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) {
			testMigrateWaitsForInFlightMigration(t, isolation)
		})
	}
}

func testMigrateWaitsForInFlightMigration(t *testing.T, isolation string) {
	t.Helper()
	s, ctx := testStoreAtIsolation(t, isolation, false)
	// An existing empty migration ledger lets an ordinary DML trigger pause
	// the first real Migrate just before commit, without a superuser event trigger.
	if _, err := s.Pool().Exec(ctx, `CREATE SCHEMA `+s.QuotedSchema()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `CREATE TABLE `+s.Table("schema_migrations")+
		` (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	key := time.Now().UnixNano()
	blocker, err := s.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key) }()
	if _, err := s.Pool().Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.block_migration() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(%d); RETURN NEW; END $$`, s.QuotedSchema(), key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `CREATE TRIGGER block_migration AFTER INSERT ON `+s.Table("schema_migrations")+
		` FOR EACH ROW EXECUTE FUNCTION `+s.QuotedSchema()+`.block_migration()`); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- s.Migrate(ctx) }()
	waitForIsolationLock(t, ctx, s.Pool(), `INSERT INTO `+s.Table("schema_migrations"))
	second := make(chan error, 1)
	go func() { second <- s.Migrate(ctx) }()
	waitForIsolationLock(t, ctx, s.Pool(), `SELECT pg_advisory_xact_lock(723901, hashtext($1))`)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Migrate after advisory lock wait: %v", err)
	}
	var count int
	query := `SELECT count(*) FROM ` + s.Table("schema_migrations") + ` WHERE version=1`
	if err := s.Pool().QueryRow(ctx, query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("migration records=%d, want 1", count)
	}
}
