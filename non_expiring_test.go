package api_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/api"
)

func TestPermanentVerificationAndMalformedExpiry(t *testing.T) {
	for _, factory := range []api.CacheFactory{nil, heldFactory} {
		s, st, token, advance := fixture(t, funcSettingsCache(factory))
		st.record.Secret.NonExpiring = true
		st.record.Secret.ExpiresAt = time.Time{}
		if factory != nil {
			if err := s.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		requireAuth(t, s, token, nil)
		advance(100 * 365 * 24 * time.Hour)
		requireAuth(t, s, token, nil)
		details, err := s.AuthenticateDetails(context.Background(), token)
		if err != nil || !details.NonExpiring || !details.ExpiresAt.IsZero() {
			t.Fatalf("details=%+v err=%v", details, err)
		}
	}
	s, st, token, _ := fixture(t)
	st.record.Secret.ExpiresAt = time.Time{}
	requireAuth(t, s, token, api.ErrUnauthorized)
	st.record.Secret.NonExpiring = true
	st.record.Secret.ExpiresAt = time.Now().Add(time.Hour)
	requireAuth(t, s, token, api.ErrUnauthorized)
}

func funcSettingsCache(factory api.CacheFactory) api.Option {
	if factory == nil {
		return api.WithClock(time.Now)
	}
	return api.WithCache(factory, 200*365*24*time.Hour)
}

func TestPermanentUnsupportedAdapter(t *testing.T) {
	_, err := api.New(&testStore{}, api.Config{DefaultTTL: time.Hour, MaxTTL: time.Hour}, api.WithNonExpiring())
	if !errors.Is(err, api.ErrUnsupported) {
		t.Fatalf("unsupported=%v", err)
	}
}
