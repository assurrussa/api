// Package api manages project-local machine-to-machine API credentials.
// Administrative methods are trusted host operations, never bearer capabilities.
package api

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalid      = errors.New("api: invalid input")
	ErrNotFound     = errors.New("api: not found")
	ErrConflict     = errors.New("api: conflict")
	ErrUnauthorized = errors.New("api: unauthorized")
	ErrForbidden    = errors.New("api: forbidden")
	ErrUnavailable  = errors.New("api: verification unavailable")
	ErrClosed       = errors.New("api: closed")
)

type Client struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	Banned    bool      `json:"banned"`
	CreatedAt time.Time `json:"created_at"`
}

// Credential is a stable access grant. Rotation changes its secret, not its ID.
type Credential struct {
	ID         string     `json:"id"`
	ClientID   string     `json:"client_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	Generation int64      `json:"generation"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// SecretVersion contains verification material, never a plaintext secret.
// ExpiresAt includes any earlier retirement deadline introduced by rotation.
type SecretVersion struct {
	ID           string
	CredentialID string
	Generation   int64
	Digest       [32]byte
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// Record must come from one consistent database statement/snapshot.
type Record struct {
	Client     Client
	Credential Credential
	Secret     SecretVersion
}

type Principal struct {
	ClientID     string   `json:"client_id"`
	CredentialID string   `json:"credential_id"`
	Scopes       []string `json:"scopes"`
}

// Issued is the only administrative result containing the plaintext token.
// Do not log or persist Token. It cannot be recovered from the store.
type Issued struct {
	Credential Credential `json:"credential"`
	Token      string     `json:"token"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

type IssueRequest struct {
	ClientID string
	Name     string
	Scopes   []string
	TTL      time.Duration // Zero uses Config.DefaultTTL.
}

type RotateRequest struct {
	CredentialID       string
	ExpectedGeneration int64
	TTL                time.Duration // Zero uses Config.DefaultTTL.
	GracePeriod        time.Duration // Zero immediately retires the current secret.
}

// Store implementations are concurrent-safe and enforce administrative invariants
// transactionally, not only in Service prechecks. Reads must use the authority's
// primary. Returned records belong to the caller, including slices and pointers.
type Store interface {
	CreateClient(ctx context.Context, client Client) error
	Client(ctx context.Context, id string) (Client, error)
	Clients(ctx context.Context, afterID string, limit int) ([]Client, error)
	SetClientScopes(ctx context.Context, id string, scopes []string) error
	SetClientBanned(ctx context.Context, id string, banned bool) error
	Issue(ctx context.Context, cred Credential, version SecretVersion) error
	Credential(ctx context.Context, id string) (Credential, error)
	Credentials(ctx context.Context, clientID, afterID string, limit int) ([]Credential, error)
	// Rotate locks client then credential; rejects banned/revoked state and a
	// mismatched generation. Only the preceding current secret's expiry is
	// shortened to min(original expiry, at+grace). Older deadlines never extend.
	Rotate(
		ctx context.Context, credID string, expectedGeneration int64, version SecretVersion, gracePeriod time.Duration, at time.Time,
	) (Credential, error)
	Revoke(ctx context.Context, id string, at time.Time) error
	RevokeAll(ctx context.Context, clientID string, at time.Time) error
	Lookup(ctx context.Context, secretID string) (Record, error)
	// Snapshot is all-or-nothing, keyed by secret version ID; expired or revoked
	// rows may be omitted. Partial query/scan/iteration results are errors.
	Snapshot(ctx context.Context) (map[string]Record, error)
}

// TimedStore is an optional Store capability for assigning Issue and Rotate
// deadlines after authority locks are acquired. Returned times are the values
// actually committed. Stores without it retain the original Store contract.
type TimedStore interface {
	IssueWithLifetime(
		ctx context.Context, cred Credential, version SecretVersion, ttl time.Duration,
	) (Credential, SecretVersion, error)
	RotateWithLifetime(
		ctx context.Context, credID string, expectedGeneration int64, version SecretVersion, ttl, grace time.Duration,
	) (Credential, SecretVersion, error)
}

// Watcher is an optional best-effort invalidation source. Watch calls invalidate
// after initial subscription and every reconnection, then on committed changes.
// It reconnects until ctx is canceled; callbacks must be serialized.
type Watcher interface {
	Watch(ctx context.Context, invalidate func()) error
}

// WatcherWithErrors optionally reports recoverable listener failures. The
// callback must not block; Watch continues reconnecting until cancellation.
type WatcherWithErrors interface {
	Watcher
	WatchWithErrors(ctx context.Context, invalidate func(), report func(error)) error
}

// ReadResult and Snapshot carry conservative monotonic freshness metadata.
type ReadResult struct {
	Record     Record
	ReadAt     time.Time
	Generation uint64
}
type Snapshot struct {
	Records    map[string]Record
	ReadAt     time.Time
	Generation uint64
}

// Source binds a cache to exactly the Service and Store it was constructed for.
type Source interface {
	Lookup(ctx context.Context, secretID string) (ReadResult, error)
	Snapshot(ctx context.Context) (Snapshot, error)
	Now() time.Time
	MaxStaleness() time.Duration
}

// Cache implementations never decide authorization. Start owns workers until
// Close; constructors must be side-effect free. Returned values are immutable.
type Cache interface {
	Start(ctx context.Context) error
	Lookup(ctx context.Context, key string, change uint64) (ReadResult, error)
	Invalidate()
	Close() error
}
type CacheFactory func(Source) (Cache, error)
