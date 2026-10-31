package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	api "github.com/assurrussa/api"
)

var (
	_ api.AuditedStore           = (*Store)(nil)
	_ api.AuditedTimedStore      = (*Store)(nil)
	_ api.AuditedRetirementStore = (*Store)(nil)
	_ api.AuditReader            = (*Store)(nil)
)

func (s *Store) bound(tx pgx.Tx) *Store {
	b := *s
	b.tx = tx
	return &b
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, event api.AuditEvent) error {
	if !event.Actor.Valid() {
		return invalid("verified human or service actor required")
	}
	details := event.Details
	if details == nil {
		details = map[string]any{}
	}
	// Read the committed result within the same transaction. This whitelist
	// deliberately excludes all verification material and host input maps.
	if event.CredentialID != "" {
		c, err := s.credential(ctx, tx, event.CredentialID, false)
		if err != nil {
			return err
		}
		event.ClientID = c.ClientID
		details["generation"] = c.Generation
		details["scopes"] = cloneScopes(c.Scopes)
		if c.RevokedAt != nil {
			details["revoked_at"] = c.RevokedAt
		}
	} else if event.Action == "client.create" || event.Action == "client.scopes" {
		var scopes []string
		if err := tx.QueryRow(ctx, `SELECT scopes FROM `+s.table("clients")+` WHERE id=$1`, event.ClientID).Scan(&scopes); err != nil {
			return err
		}
		details["scopes"] = scopes
	}
	if event.VersionID != "" {
		var expiresAt time.Time
		query := `SELECT expires_at FROM ` + s.table("secret_versions") + ` WHERE id=$1`
		if err := tx.QueryRow(ctx, query, event.VersionID).Scan(&expiresAt); err != nil {
			return err
		}
		details["expires_at"] = expiresAt
	}
	body, err := json.Marshal(details)
	if err != nil {
		return err
	}
	query := `INSERT INTO ` + s.table("audit_events") +
		`(actor_kind,actor_id,action,client_id,credential_id,version_id,operation_id,occurred_at,details)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	_, err = tx.Exec(ctx, query, event.Actor.Kind, event.Actor.ID, event.Action, event.ClientID,
		event.CredentialID, event.VersionID, event.OperationID, time.Now().UTC(), body)
	return err
}

func (s *Store) audited(ctx context.Context, event api.AuditEvent, f func(*Store) error) error {
	if !event.Actor.Valid() {
		return invalid("verified human or service actor required")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if err := f(s.bound(tx)); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, event)
	})
}

func (s *Store) CreateClientAudited(ctx context.Context, a api.Actor, c api.Client) error {
	event := api.AuditEvent{
		Actor: a, Action: "client.create", ClientID: c.ID,
	}
	return s.audited(ctx, event, func(b *Store) error { return b.CreateClient(ctx, c) })
}

func (s *Store) SetClientScopesAudited(ctx context.Context, a api.Actor, id string, scopes []string) error {
	event := api.AuditEvent{
		Actor: a, Action: "client.scopes", ClientID: id,
	}
	return s.audited(ctx, event, func(b *Store) error { return b.SetClientScopes(ctx, id, scopes) })
}

func (s *Store) SetClientBannedAudited(ctx context.Context, a api.Actor, id string, banned bool) error {
	event := api.AuditEvent{
		Actor: a, Action: "client.ban", ClientID: id, Details: map[string]any{"banned": banned},
	}
	return s.audited(ctx, event, func(b *Store) error { return b.SetClientBanned(ctx, id, banned) })
}

func (s *Store) IssueAudited(ctx context.Context, a api.Actor, c api.Credential, v api.SecretVersion) error {
	event := api.AuditEvent{
		Actor: a, Action: "credential.issue", ClientID: c.ClientID, CredentialID: c.ID, VersionID: v.ID,
	}
	return s.audited(ctx, event, func(b *Store) error { return b.Issue(ctx, c, v) })
}

func (s *Store) IssueWithLifetimeAudited(
	ctx context.Context,
	a api.Actor,
	c api.Credential,
	v api.SecretVersion,
	ttl time.Duration,
) (api.Credential, api.SecretVersion, error) {
	var result api.Credential
	var version api.SecretVersion
	event := api.AuditEvent{
		Actor: a, Action: "credential.issue", ClientID: c.ClientID, CredentialID: c.ID, VersionID: v.ID,
	}
	err := s.audited(ctx, event, func(b *Store) error {
		var err error
		result, version, err = b.IssueWithLifetime(ctx, c, v, ttl)
		return err
	})
	if err != nil {
		return api.Credential{}, api.SecretVersion{}, err
	}
	return result, version, nil
}

func (s *Store) RotateAudited(
	ctx context.Context,
	a api.Actor,
	id string,
	expected int64,
	v api.SecretVersion,
	grace time.Duration,
	at time.Time,
) (api.Credential, error) {
	var result api.Credential
	event := api.AuditEvent{
		Actor: a, Action: "credential.rotate", CredentialID: id, VersionID: v.ID,
	}
	err := s.audited(ctx, event, func(b *Store) error {
		var err error
		result, err = b.Rotate(ctx, id, expected, v, grace, at)
		return err
	})
	if err != nil {
		return api.Credential{}, err
	}
	return result, nil
}

func (s *Store) RotateWithLifetimeAudited(
	ctx context.Context,
	a api.Actor,
	id string,
	expected int64,
	v api.SecretVersion,
	ttl,
	grace time.Duration,
) (api.Credential, api.SecretVersion, error) {
	var result api.Credential
	var version api.SecretVersion
	event := api.AuditEvent{
		Actor: a, Action: "credential.rotate", CredentialID: id, VersionID: v.ID,
	}
	err := s.audited(ctx, event, func(b *Store) error {
		var err error
		result, version, err = b.RotateWithLifetime(ctx, id, expected, v, ttl, grace)
		return err
	})
	if err != nil {
		return api.Credential{}, api.SecretVersion{}, err
	}
	return result, version, nil
}

func (s *Store) RevokeAudited(ctx context.Context, a api.Actor, id string, at time.Time) error {
	event := api.AuditEvent{
		Actor: a, Action: "credential.revoke", CredentialID: id,
	}
	return s.audited(ctx, event, func(b *Store) error { return b.Revoke(ctx, id, at) })
}

func (s *Store) RevokeAllAudited(ctx context.Context, a api.Actor, id string, at time.Time) error {
	event := api.AuditEvent{
		Actor: a, Action: "client.revoke_all", ClientID: id,
		Details: map[string]any{"revoked_at": at},
	}
	return s.audited(ctx, event, func(b *Store) error { return b.RevokeAll(ctx, id, at) })
}

func (s *Store) RetireVersionAudited(ctx context.Context, a api.Actor, id, versionID string) error {
	event := api.AuditEvent{
		Actor: a, Action: "version.retire", CredentialID: id, VersionID: versionID,
	}
	return s.audited(ctx, event, func(b *Store) error { return b.RetireVersion(ctx, id, versionID) })
}

func (s *Store) AuditEvents(ctx context.Context, before int64, limit int) ([]api.AuditEvent, error) {
	if before < 0 || limit < 1 || limit > 1000 {
		return nil, invalid("nonnegative cursor and limit 1..1000 required")
	}
	query := `SELECT id,actor_kind,actor_id,action,client_id,credential_id,version_id,operation_id,occurred_at,details
 FROM ` + s.table("audit_events") + ` WHERE ($1::bigint=0 OR id<$1) ORDER BY id DESC LIMIT $2`
	rows, err := s.pool.Query(ctx, query, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]api.AuditEvent, 0)
	for rows.Next() {
		var e api.AuditEvent
		var body []byte
		if err = rows.Scan(&e.ID, &e.Actor.Kind, &e.Actor.ID, &e.Action, &e.ClientID,
			&e.CredentialID, &e.VersionID, &e.OperationID, &e.OccurredAt, &body); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(body, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || before.After(time.Now()) || limit < 1 || limit > 1000 {
		return 0, invalid("past cutoff and limit 1..1000 required")
	}
	var removed int64
	query := `WITH candidates AS (SELECT id FROM ` + s.table("audit_events") + `
 WHERE occurred_at<$1 ORDER BY occurred_at,id LIMIT $2 FOR UPDATE SKIP LOCKED),
 deleted AS (DELETE FROM ` + s.table("audit_events") + ` e USING candidates c WHERE e.id=c.id RETURNING e.id)
 SELECT count(*) FROM deleted`
	err := s.pool.QueryRow(ctx, query, before, limit).Scan(&removed)
	return removed, err
}
