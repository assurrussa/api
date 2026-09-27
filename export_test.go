package api

import "time"

// MaxTrackedChanges is the maximum number of recent client/credential changes tracked in memory.
const MaxTrackedChanges = maxTrackedChanges

// ParseToken parses the token into lookup ID and secret digest.
func ParseToken(raw string) (string, [32]byte, error) {
	return parseToken(raw)
}

// CloneRecord returns a deep copy of a Record.
func CloneRecord(r Record) Record {
	return cloneRecord(r)
}

// WithClock overrides the clock function for testing.
func WithClock(clock func() time.Time) Option {
	return func(s *settings) error {
		s.now = clock
		return nil
	}
}

// InvalidateFor tests change notifications for client and credential IDs.
func (s *Service) InvalidateFor(clientID, credentialID string) {
	s.invalidateFor(clientID, credentialID)
}

// Secret issues a secret version directly for policy testing.
func (s *Service) Secret(clientID string, generation int64, ttl time.Duration) (SecretVersion, string, error) {
	return s.secret(clientID, generation, ttl)
}

// TrackedChangesCount returns the count of tracked changes and unknown change counter.
func (s *Service) TrackedChangesCount() (int, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clientChange) + len(s.credentialChange), s.unknownChange
}
