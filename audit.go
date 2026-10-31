package api

import (
	"context"
	"fmt"
	"time"
)

// WithAudit requires transactional audit support and a host-verified Actor for writes.
func WithAudit() Option { return func(s *settings) error { s.audit = true; return nil } }

func validateCapabilities(store Store, opt settings) error {
	if opt.audit {
		if _, ok := store.(AuditedStore); !ok {
			return fmt.Errorf("%w: transactional audit", ErrUnsupported)
		}
		if _, timed := store.(TimedStore); timed {
			if _, ok := store.(AuditedTimedStore); !ok {
				return fmt.Errorf("%w: timed transactional audit", ErrUnsupported)
			}
		}
	}
	if opt.usage != nil {
		if _, ok := store.(UsageStore); !ok {
			return fmt.Errorf("%w: usage tracking", ErrUnsupported)
		}
	}
	return nil
}

func (s *Service) actor(ctx context.Context) (Actor, error) {
	if !s.settings.audit {
		return Actor{}, nil
	}
	a, ok := ActorFromContext(ctx)
	if !ok || !a.Valid() {
		return Actor{}, fmt.Errorf("%w: audit actor required", ErrInvalid)
	}
	return a, nil
}

func (s *Service) adminStore(ctx context.Context) (Store, error) {
	if !s.settings.audit {
		return s.store, nil
	}
	actor, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	audit, ok := s.store.(AuditedStore)
	if !ok {
		return nil, ErrUnsupported
	}
	adapter := auditedAdapter{Store: s.store, audit: audit, actor: actor}
	if timed, ok := s.store.(AuditedTimedStore); ok {
		if _, supported := s.store.(TimedStore); supported {
			return auditedTimedAdapter{auditedAdapter: adapter, timed: timed}, nil
		}
	}
	return adapter, nil
}

type auditedAdapter struct {
	Store
	audit AuditedStore
	actor Actor
}

func (a auditedAdapter) CreateClient(ctx context.Context, c Client) error {
	return a.audit.CreateClientAudited(ctx, a.actor, c)
}

func (a auditedAdapter) SetClientScopes(ctx context.Context, id string, scopes []string) error {
	return a.audit.SetClientScopesAudited(ctx, a.actor, id, scopes)
}

func (a auditedAdapter) SetClientBanned(ctx context.Context, id string, banned bool) error {
	return a.audit.SetClientBannedAudited(ctx, a.actor, id, banned)
}

func (a auditedAdapter) Issue(ctx context.Context, c Credential, v SecretVersion) error {
	return a.audit.IssueAudited(ctx, a.actor, c, v)
}

func (a auditedAdapter) Rotate(
	ctx context.Context, id string, generation int64, v SecretVersion, grace time.Duration, at time.Time,
) (Credential, error) {
	return a.audit.RotateAudited(ctx, a.actor, id, generation, v, grace, at)
}

func (a auditedAdapter) Revoke(ctx context.Context, id string, at time.Time) error {
	return a.audit.RevokeAudited(ctx, a.actor, id, at)
}

func (a auditedAdapter) RevokeAll(ctx context.Context, id string, at time.Time) error {
	return a.audit.RevokeAllAudited(ctx, a.actor, id, at)
}

type auditedTimedAdapter struct {
	auditedAdapter
	timed AuditedTimedStore
}

func (a auditedTimedAdapter) IssueWithLifetime(
	ctx context.Context, c Credential, v SecretVersion, ttl time.Duration,
) (Credential, SecretVersion, error) {
	return a.timed.IssueWithLifetimeAudited(ctx, a.actor, c, v, ttl)
}

func (a auditedTimedAdapter) RotateWithLifetime(
	ctx context.Context, id string, generation int64, v SecretVersion, ttl, grace time.Duration,
) (Credential, SecretVersion, error) {
	return a.timed.RotateWithLifetimeAudited(ctx, a.actor, id, generation, v, ttl, grace)
}
