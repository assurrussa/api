package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api/postgres"
)

func waitWatchTime(t *testing.T, events <-chan time.Time) time.Time {
	t.Helper()
	select {
	case at := <-events:
		return at
	case <-time.After(10 * time.Second):
		t.Fatal("listener event was not reported")
		return time.Time{}
	}
}

func TestWatchBackoffBeforeSubscription(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, err := pgxpool.ParseConfig("postgres://127.0.0.1:1/test?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		attempts := make(chan time.Time, 1)
		hookErr := errors.New("listener cannot connect")
		config.BeforeConnect = func(_ context.Context, _ *pgx.ConnConfig) error {
			attempts <- time.Now()
			return hookErr
		}
		pool, err := pgxpool.NewWithConfig(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		store, err := postgres.New(pool, "watch_backoff")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		reported := make(chan error, 1)
		go func() {
			done <- store.WatchWithErrors(ctx, func() {
				t.Error("failed connection invalidated the cache")
			}, func(err error) { reported <- err })
		}()
		previous := waitWatchTime(t, attempts)
		for _, want := range []time.Duration{
			100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond,
			800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond,
			5 * time.Second, 5 * time.Second,
		} {
			if err := <-reported; !errors.Is(err, hookErr) {
				t.Fatalf("connection failure was not preserved: %v", err)
			}
			attemptedAt := waitWatchTime(t, attempts)
			if delay := attemptedAt.Sub(previous); delay != want {
				t.Fatalf("failed attempt retry wait: got %v, want %v", delay, want)
			}
			previous = attemptedAt
		}
		<-reported
		synctest.Wait()
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("canceled retry wait: %v", err)
		}
		select {
		case <-attempts:
			t.Fatal("listener retried after cancellation")
		default:
		}
	})
}

type watchFailure struct {
	at  time.Time
	err error
}

func TestWatchBackoffAfterConnectFailure(t *testing.T) {
	hookErr := errors.New("listener setup failed")
	testWatchSetupBackoff(t, func(context.Context, *pgx.Conn) error { return hookErr }, func(err error) bool {
		return errors.Is(err, hookErr)
	})
}

func TestWatchBackoffAfterListenFailure(t *testing.T) {
	testWatchSetupBackoff(t, func(ctx context.Context, conn *pgx.Conn) error {
		// Leave a failed transaction so LISTEN fails after AfterConnect succeeds.
		_, err := conn.Exec(ctx, "BEGIN; SELECT 1/0")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "22012" {
			return errors.New("could not prepare failed listener transaction")
		}
		return nil
	}, func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "25P02"
	})
}

func testWatchSetupBackoff(t *testing.T, afterConnect func(context.Context, *pgx.Conn) error, matches func(error) bool) {
	t.Helper()
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("API_TEST_DATABASE_URL required")
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	attempts := make(chan time.Time, 10)
	config.BeforeConnect = func(_ context.Context, _ *pgx.ConnConfig) error {
		attempts <- time.Now()
		return nil
	}
	config.AfterConnect = afterConnect
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := postgres.New(pool, "watch_setup_backoff")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	failures := make(chan watchFailure, 10)
	done := make(chan error, 1)
	go func() {
		done <- store.WatchWithErrors(ctx, func() {
			t.Error("failed listener setup invalidated the cache")
		}, func(err error) { failures <- watchFailure{at: time.Now(), err: err} })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("canceled retry wait: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("listener did not stop after cancellation")
		}
	})
	waitWatchTime(t, attempts)
	for _, want := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond} {
		var failure watchFailure
		select {
		case failure = <-failures:
		case <-time.After(5 * time.Second):
			t.Fatal("listener setup failure was not reported")
		}
		if !matches(failure.err) {
			t.Fatalf("unexpected listener setup error: %v", failure.err)
		}
		if delay := waitWatchTime(t, attempts).Sub(failure.at); delay < want {
			t.Fatalf("failed listener setup reset retry backoff: got %v, want at least %v", delay, want)
		}
	}
}
