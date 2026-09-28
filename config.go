package api

import (
	"fmt"
	"time"
)

type Config struct {
	Scopes     []string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

type settings struct {
	factory      CacheFactory
	maxStaleness time.Duration
	now          func() time.Time
}
type Option func(*settings) error

// WithCache opts into bounded-staleness verification. The duration is mandatory
// and may be seconds or minutes. Expiry of the actual secret is always enforced.
func WithCache(factory CacheFactory, maxStaleness time.Duration) Option {
	return func(s *settings) error {
		if factory == nil || maxStaleness <= 0 {
			return fmt.Errorf("%w: cache factory and positive max staleness required", ErrInvalid)
		}
		s.factory, s.maxStaleness = factory, maxStaleness
		return nil
	}
}
