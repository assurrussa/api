package api

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported means the configured adapter lacks an optional capability.
var ErrUnsupported = errors.New("api: unsupported capability")

// Actor is an identity verified by the trusted host, never by a business token.
type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type actorKey struct{}

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}
func (a Actor) Valid() bool { return (a.Kind == "human" || a.Kind == "service") && validName(a.ID) }

// SecretVersionInfo contains safe administrative metadata only.
type SecretVersionInfo struct {
	ID           string     `json:"id"`
	CredentialID string     `json:"credential_id"`
	Generation   int64      `json:"generation"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}
type CredentialDetails struct {
	Credential        Credential        `json:"credential"`
	ClientBanned      bool              `json:"client_banned"`
	EffectiveScopes   []string          `json:"effective_scopes"`
	CurrentVersion    SecretVersionInfo `json:"current_version"`
	UnexpiredVersions int               `json:"unexpired_versions"`
	LastUsedAt        *time.Time        `json:"last_used_at,omitempty"`
}
type AuthenticationDetails struct {
	Principal       Principal `json:"principal"`
	SecretVersionID string    `json:"secret_version_id"`
	Generation      int64     `json:"generation"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type ManagementStore interface {
	CredentialDetails(ctx context.Context, id string) (CredentialDetails, error)
	SecretVersions(ctx context.Context, id string, before int64, limit int) ([]SecretVersionInfo, error)
	RetireVersion(ctx context.Context, credentialID, versionID string) error
}
type AuditedRetirementStore interface {
	RetireVersionAudited(ctx context.Context, actor Actor, credentialID, versionID string) error
}

// OperationSpec identifies a logical request. Fingerprint is a SHA-256 of its
// normalized requested parameters and actor (when auditing is enabled).
type OperationSpec struct {
	ID          string
	Fingerprint [32]byte
}

// OperationReceipt is immutable proof of a committed operation, not current state.
// It never contains a token or verification digest. Retain it without expiration.
type OperationReceipt struct {
	Fingerprint [32]byte          `json:"-"`
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Credential  Credential        `json:"credential"`
	Version     SecretVersionInfo `json:"version"`
	CommittedAt time.Time         `json:"committed_at"`
}
type OperationResult struct {
	Receipt OperationReceipt `json:"receipt"`
	Issued  *Issued          `json:"issued,omitempty"`
}

// OperationStore commits receipt and mutation atomically. A matching replay is
// checked before current client/generation policy; it returns applied=false.
// ErrNotFound from Operation means not observed, not proof of rollback.
type OperationStore interface {
	Operation(ctx context.Context, id string) (OperationReceipt, error)
	IssueOnce(
		ctx context.Context, spec OperationSpec, credential Credential, version SecretVersion, ttl time.Duration,
	) (OperationReceipt, bool, error)
	RotateOnce(
		ctx context.Context, spec OperationSpec, id string, generation int64, version SecretVersion, ttl, grace time.Duration,
	) (OperationReceipt, bool, error)
}
type AuditedOperationStore interface {
	IssueOnceAudited(
		ctx context.Context, actor Actor, spec OperationSpec, credential Credential, version SecretVersion, ttl time.Duration,
	) (OperationReceipt, bool, error)
	RotateOnceAudited(
		ctx context.Context, actor Actor, spec OperationSpec, id string, generation int64,
		version SecretVersion, ttl, grace time.Duration,
	) (OperationReceipt, bool, error)
}

// AuditedStore implementations record every successful administrative command
// in the same transaction as its mutation, and reject invalid actors.
type AuditedStore interface {
	CreateClientAudited(ctx context.Context, actor Actor, client Client) error
	SetClientScopesAudited(ctx context.Context, actor Actor, id string, scopes []string) error
	SetClientBannedAudited(ctx context.Context, actor Actor, id string, banned bool) error
	IssueAudited(ctx context.Context, actor Actor, credential Credential, version SecretVersion) error
	RotateAudited(
		ctx context.Context, actor Actor, id string, generation int64, version SecretVersion, grace time.Duration, at time.Time,
	) (Credential, error)
	RevokeAudited(ctx context.Context, actor Actor, id string, at time.Time) error
	RevokeAllAudited(ctx context.Context, actor Actor, id string, at time.Time) error
}
type AuditedTimedStore interface {
	IssueWithLifetimeAudited(
		ctx context.Context, actor Actor, credential Credential, version SecretVersion, ttl time.Duration,
	) (Credential, SecretVersion, error)
	RotateWithLifetimeAudited(
		ctx context.Context, actor Actor, id string, generation int64, version SecretVersion, ttl, grace time.Duration,
	) (Credential, SecretVersion, error)
}
type AuditEvent struct {
	ID           int64     `json:"id"`
	Actor        Actor     `json:"actor"`
	Action       string    `json:"action"`
	ClientID     string    `json:"client_id,omitempty"`
	CredentialID string    `json:"credential_id,omitempty"`
	VersionID    string    `json:"version_id,omitempty"`
	OperationID  string    `json:"operation_id,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
	// Details is a whitelist of safe result metadata, never secrets or digests.
	Details map[string]any `json:"details,omitempty"`
}
type AuditReader interface {
	AuditEvents(ctx context.Context, before int64, limit int) ([]AuditEvent, error)
	PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error)
}
type UsageObservation struct {
	ClientID     string
	CredentialID string
	VersionID    string
	At           time.Time
}

// UsageStore merges times monotonically without authorization invalidation.
// Missing/pruned versions are ignored, never reinserted.
type UsageStore interface {
	RecordUsage(ctx context.Context, observations []UsageObservation) error
}
type UsageConfig struct {
	FlushInterval time.Duration
	FlushTimeout  time.Duration
	CloseTimeout  time.Duration
	BatchSize     int
	MaxPending    int
}
type UsageStats struct {
	Started     bool      `json:"started"`
	Pending     int       `json:"pending"`
	Dropped     uint64    `json:"dropped"`
	LastFlushAt time.Time `json:"last_flush_at"`
}
