package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/assurrussa/api"
)

func TestPermanentLifetimeUsesAuthorityTimeAfterLocks(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.CreateClient(ctx, client("permanent-lock")); err != nil {
		t.Fatal(err)
	}
	c, v := grant("permanent-lock", "permanent")
	v.NonExpiring = true
	v.ExpiresAt = time.Time{}
	c.CreatedAt = time.Now().Add(-time.Hour)
	v.CreatedAt = c.CreatedAt
	issued, v, err := s.IssueWithLifetime(ctx, c, v, 0)
	if err != nil {
		t.Fatal(err)
	}
	if issued.CreatedAt.Before(time.Now().Add(-time.Second)) || !issued.CreatedAt.Equal(v.CreatedAt) {
		t.Fatal("permanent issue used caller time")
	}
	lock, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err = lock.Exec(ctx, `SELECT id FROM `+s.Table("clients")+` WHERE id=$1 FOR UPDATE`, c.ClientID); err != nil {
		t.Fatal(err)
	}
	next := v
	next.ID = "permanent_v2"
	next.Generation = 2
	next.CreatedAt = time.Now().Add(-time.Hour)
	type result struct {
		v   api.SecretVersion
		err error
	}
	done := make(chan result, 1)
	go func() {
		_, version, e := s.RotateWithLifetime(ctx, c.ID, 1, next, 0, time.Second)
		done <- result{version, e}
	}()
	select {
	case r := <-done:
		t.Fatalf("rotation did not wait: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
	unlockedAt := time.Now().UTC()
	if err = lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.v.CreatedAt.Before(unlockedAt) || !r.v.NonExpiring || !r.v.ExpiresAt.IsZero() {
			t.Fatalf("committed version=%+v", r.v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotation blocked")
	}
	old, err := s.Lookup(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Secret.NonExpiring || old.Secret.ExpiresAt.Before(unlockedAt.Add(time.Second)) {
		t.Fatalf("old grace=%+v", old.Secret)
	}
}
