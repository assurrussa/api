package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Service owns verification and optional workers, but never the Store's pool.
// New is side-effect free. Strict verification needs no Start; caches do.
type Service struct {
	store            Store
	cfg              Config
	settings         settings
	allowed          map[string]struct{}
	cache            Cache
	mu               sync.RWMutex
	generation       uint64
	unknownChange    uint64
	clientChange     map[string]uint64
	credentialChange map[string]uint64
	started, closed  bool
	startMu          sync.Mutex
	closeMu          sync.Mutex
	life             context.Context //nolint:containedctx // Service holds lifecycle context for background workers.
	cancel           context.CancelFunc
	stopParent       func() bool
	active           sync.WaitGroup
	workers          sync.WaitGroup
	errors           chan error
	reportMu         sync.Mutex
	lastReport       map[string]time.Time
}

const maxTrackedChanges = 1024

func New(store Store, cfg Config, options ...Option) (*Service, error) {
	if store == nil || cfg.DefaultTTL <= 0 || cfg.MaxTTL < cfg.DefaultTTL {
		return nil, fmt.Errorf("%w: store, positive default TTL and maximum TTL required", ErrInvalid)
	}
	opt := settings{now: time.Now}
	for _, option := range options {
		if option == nil {
			return nil, ErrInvalid
		}
		if err := option(&opt); err != nil {
			return nil, err
		}
	}
	allowed := make(map[string]struct{}, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		if !validScope(scope) {
			return nil, fmt.Errorf("%w: scope", ErrInvalid)
		}
		allowed[scope] = struct{}{}
	}
	cfg.Scopes = slices.Clone(cfg.Scopes)
	life, cancel := context.WithCancel(context.Background())
	s := &Service{
		store:            store,
		cfg:              cfg,
		settings:         opt,
		allowed:          allowed,
		life:             life,
		cancel:           cancel,
		errors:           make(chan error, 8),
		clientChange:     make(map[string]uint64),
		credentialChange: make(map[string]uint64),
		lastReport:       make(map[string]time.Time),
	}
	if opt.factory != nil {
		var err error
		s.cache, err = opt.factory(serviceSource{s})
		if err != nil {
			cancel()
			return nil, err
		}
		if s.cache == nil {
			cancel()
			return nil, fmt.Errorf("%w: nil cache", ErrInvalid)
		}
	}
	return s, nil
}

// Start begins optional cache and notification workers. It may be called once.
// Canceling ctx stops workers and makes further operations unavailable.
func (s *Service) Start(ctx context.Context) error {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if ctx == nil {
		return ErrInvalid
	}
	s.mu.RLock()
	closed, started := s.closed, s.started
	s.mu.RUnlock()
	if closed || s.life.Err() != nil {
		return ErrClosed
	}
	if started {
		return ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.stopParent = context.AfterFunc(ctx, s.cancel)
	if s.cache != nil {
		if err := s.cache.Start(s.life); err != nil { //nolint:contextcheck // Cache lifecycle uses service context.
			s.stopParent()
			s.cancel()
			return err
		}
	}
	s.mu.Lock()
	if s.closed || s.life.Err() != nil {
		s.mu.Unlock()
		return ErrClosed
	}
	s.started = true
	s.mu.Unlock()
	if watcher, ok := s.store.(Watcher); ok && s.cache != nil {
		s.startWatcher(watcher)
	}
	return nil
}

func (s *Service) startWatcher(watcher Watcher) {
	s.workers.Go(func() {
		var err error
		if observed, ok := watcher.(WatcherWithErrors); ok {
			err = observed.WatchWithErrors(s.life, s.invalidate, func(err error) { s.report("watch", err) })
		} else {
			err = watcher.Watch(s.life, s.invalidate)
		}
		if s.life.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("invalidation watcher stopped")
		}
		s.invalidate()
		s.report("watch stopped", err)
	})
}

// Errors reports recoverable cache/notification failures and unexpected watcher
// termination. Delivery is nonblocking and rate limited; use separate metrics
// for counting every failure. Freshness deadlines still apply.
func (s *Service) Errors() <-chan error { return s.errors }

func (s *Service) report(kind string, err error) {
	if err == nil || s.life.Err() != nil {
		return
	}
	s.reportMu.Lock()
	now := time.Now()
	if now.Sub(s.lastReport[kind]) < 30*time.Second {
		s.reportMu.Unlock()
		return
	}
	s.lastReport[kind] = now
	s.reportMu.Unlock()
	select {
	case s.errors <- fmt.Errorf("%w: %s: %w", ErrUnavailable, kind, err):
	default:
	}
}

// Close cancels workers and in-flight operations and waits for their completion.
func (s *Service) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.generation++
	s.mu.Unlock()
	// Cancel before waiting for Start: its initial cache load may itself need
	// this cancellation to finish. closeMu serializes concurrent finalizers.
	s.cancel()
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.stopParent != nil {
		s.stopParent()
	}
	var err error
	if s.cache != nil {
		err = s.cache.Close()
	}
	s.workers.Wait()
	s.active.Wait()
	close(s.errors)
	return err
}

func (s *Service) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	if s.closed || s.life.Err() != nil {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	s.active.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.life, cancel)
	return call, func() { stop(); cancel(); s.active.Done() }, nil
}

func (s *Service) invalidate() {
	s.invalidateFor("", "")
}

// invalidateFor records the affected identity as well as invalidating the
// whole cache. An external notification has no identity and fences all reads.
func (s *Service) invalidateFor(clientID, credentialID string) {
	s.mu.Lock()
	s.generation++
	if clientID == "" && credentialID == "" {
		s.unknownChange = s.generation
	}
	if clientID != "" {
		s.clientChange[clientID] = s.generation
	}
	if credentialID != "" {
		s.credentialChange[credentialID] = s.generation
	}
	if len(s.clientChange)+len(s.credentialChange) > maxTrackedChanges {
		// Older in-flight reads may have crossed a discarded change. Fence
		// them all while bounding metadata in long-lived strict services too.
		s.unknownChange = s.generation
		clear(s.clientChange)
		clear(s.credentialChange)
	}
	s.mu.Unlock()
	if s.cache != nil {
		s.cache.Invalidate()
	}
}

// Authenticate verifies the secret and every requested scope. No returned slice
// aliases the Store or cache. Errors never include the supplied token.
func (s *Service) Authenticate(ctx context.Context, token string, required ...string) (Principal, error) {
	ctx, done, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer done()
	key, digest, err := parseToken(token)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	s.mu.RLock()
	started := s.started
	s.mu.RUnlock()
	if s.cache != nil && !started {
		return Principal{}, fmt.Errorf("%w: cache not started", ErrUnavailable)
	}
	forceSource := false
	for attempt := 0; attempt < 3; attempt++ {
		s.mu.RLock()
		generation := s.generation
		s.mu.RUnlock()
		var read ReadResult
		if s.cache == nil || forceSource {
			read, err = (serviceSource{s}).Lookup(ctx, key)
		} else {
			read, err = s.cache.Lookup(ctx, key, generation)
		}
		if err != nil {
			if ctx.Err() != nil {
				return Principal{}, ctx.Err()
			}
			if errors.Is(err, ErrNotFound) {
				return Principal{}, ErrUnauthorized
			}
			return Principal{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		// This lock is the local decision linearization point. No external code
		// runs here; invalidation cannot race the final successful decision.
		s.mu.RLock()
		if s.closed || s.life.Err() != nil {
			s.mu.RUnlock()
			return Principal{}, ErrClosed
		}
		if err := ctx.Err(); err != nil {
			s.mu.RUnlock()
			return Principal{}, err
		}
		if read.Generation < s.unknownChange ||
			read.Generation < s.clientChange[read.Record.Client.ID] ||
			read.Generation < s.credentialChange[read.Record.Credential.ID] {
			s.mu.RUnlock()
			forceSource = true
			continue
		}
		now := s.settings.now()
		if s.cache != nil && (read.ReadAt.IsZero() || !now.Before(read.ReadAt.Add(s.settings.maxStaleness))) {
			s.mu.RUnlock()
			forceSource = true
			continue
		}
		principal, checkErr := validate(read.Record, key, digest, now, required)
		s.mu.RUnlock()
		return principal, checkErr
	}
	return Principal{}, fmt.Errorf("%w: verification changed or exceeded freshness budget", ErrUnavailable)
}

func validate(r Record, key string, digest [32]byte, now time.Time, required []string) (Principal, error) {
	if r.Secret.ID != key || r.Secret.CredentialID != r.Credential.ID || r.Credential.ClientID != r.Client.ID ||
		subtle.ConstantTimeCompare(r.Secret.Digest[:], digest[:]) != 1 || r.Client.Banned || r.Credential.RevokedAt != nil ||
		r.Secret.ExpiresAt.IsZero() || !now.Before(r.Secret.ExpiresAt) {
		return Principal{}, ErrUnauthorized
	}
	scopes := make([]string, 0, len(r.Credential.Scopes))
	for _, scope := range r.Credential.Scopes {
		if slices.Contains(r.Client.Scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	for _, scope := range required {
		if !slices.Contains(scopes, scope) {
			return Principal{}, ErrForbidden
		}
	}
	return Principal{ClientID: r.Client.ID, CredentialID: r.Credential.ID, Scopes: scopes}, nil
}

type serviceSource struct{ service *Service }

func (src serviceSource) ReportCacheError(err error) { src.service.report("cache refresh", err) }

func (src serviceSource) Now() time.Time              { return src.service.settings.now() }
func (src serviceSource) MaxStaleness() time.Duration { return src.service.settings.maxStaleness }

func (src serviceSource) stamp() (time.Time, uint64) {
	src.service.mu.RLock()
	defer src.service.mu.RUnlock()
	return src.service.settings.now(), src.service.generation
}

func (src serviceSource) Lookup(ctx context.Context, id string) (ReadResult, error) {
	at, generation := src.stamp()
	record, err := src.service.store.Lookup(ctx, id)
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Record: cloneRecord(record), ReadAt: at, Generation: generation}, nil
}

func (src serviceSource) Snapshot(ctx context.Context) (Snapshot, error) {
	at, generation := src.stamp()
	records, err := src.service.store.Snapshot(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	copyRecords := make(map[string]Record, len(records))
	for key, record := range records {
		copyRecords[key] = cloneRecord(record)
	}
	return Snapshot{Records: copyRecords, ReadAt: at, Generation: generation}, nil
}

func cloneRecord(r Record) Record {
	r.Client.Scopes = slices.Clone(r.Client.Scopes)
	r.Credential.Scopes = slices.Clone(r.Credential.Scopes)
	if r.Credential.RevokedAt != nil {
		at := *r.Credential.RevokedAt
		r.Credential.RevokedAt = &at
	}
	return r
}

func validScope(scope string) bool {
	if len(scope) == 0 || len(scope) > 128 {
		return false
	}
	for _, c := range scope {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

func (s *Service) scopes(input []string) ([]string, error) {
	result := make([]string, 0, len(input))
	for _, scope := range input {
		if _, ok := s.allowed[scope]; !ok {
			return nil, fmt.Errorf("%w: unknown scope", ErrInvalid)
		}
		result = append(result, scope)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func newID() string              { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func validName(name string) bool { return strings.TrimSpace(name) != "" && len(name) <= 256 }

func (s *Service) secret(credential string, generation int64, ttl time.Duration) (SecretVersion, string, error) {
	ttl, err := s.effectiveTTL(ttl)
	if err != nil {
		return SecretVersion{}, "", fmt.Errorf("%w: token TTL", ErrInvalid)
	}
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	at := s.settings.now().UTC()
	version := SecretVersion{
		ID:           newID(),
		CredentialID: credential,
		Generation:   generation,
		Digest:       sha256.Sum256(raw[:]),
		CreatedAt:    at,
		ExpiresAt:    at.Add(ttl),
	}
	return version, "api1_" + version.ID + "." + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *Service) effectiveTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		ttl = s.cfg.DefaultTTL
	}
	if ttl <= 0 || ttl > s.cfg.MaxTTL {
		return 0, ErrInvalid
	}
	return ttl, nil
}

func parseToken(token string) (string, [32]byte, error) {
	var zero [32]byte
	if len(token) != 81 || !strings.HasPrefix(token, "api1_") || token[37] != '.' {
		return "", zero, ErrUnauthorized
	}
	id := token[5:37]
	if _, err := hex.DecodeString(id); err != nil || strings.ToLower(id) != id {
		return "", zero, ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[38:])
	if err != nil || len(raw) != 32 {
		return "", zero, ErrUnauthorized
	}
	return id, sha256.Sum256(raw), nil
}
