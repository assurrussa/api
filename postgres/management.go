package postgres

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	api "github.com/assurrussa/api"
)

var (
	_ api.ManagementStore = (*Store)(nil)
	_ api.UsageStore      = (*Store)(nil)
)

// CredentialDetails obtains policy and version metadata from a single primary
// statement, so concurrent rotations cannot mix generations in the result.
func (s *Store) CredentialDetails(ctx context.Context, id string) (api.CredentialDetails, error) {
	var d api.CredentialDetails
	var clientScopes []string
	query := `SELECT k.id,k.client_id,k.name,k.scopes,k.generation,k.revoked_at,k.created_at,
 c.banned,c.scopes,k.last_used_at,v.id,v.credential_id,v.generation,v.created_at,v.expires_at,v.last_used_at,
 (SELECT count(*) FROM ` + s.table("secret_versions") + ` h WHERE h.credential_id=k.id AND h.expires_at>statement_timestamp())
 FROM ` + s.table("credentials") + ` k JOIN ` + s.table("clients") + ` c ON c.id=k.client_id
 JOIN ` + s.table("secret_versions") + ` v ON v.credential_id=k.id AND v.generation=k.generation WHERE k.id=$1`
	err := s.pool.QueryRow(ctx, query, id).Scan(&d.Credential.ID, &d.Credential.ClientID, &d.Credential.Name, &d.Credential.Scopes,
		&d.Credential.Generation, &d.Credential.RevokedAt, &d.Credential.CreatedAt, &d.ClientBanned, &clientScopes, &d.LastUsedAt,
		&d.CurrentVersion.ID, &d.CurrentVersion.CredentialID, &d.CurrentVersion.Generation,
		&d.CurrentVersion.CreatedAt, &d.CurrentVersion.ExpiresAt, &d.CurrentVersion.LastUsedAt, &d.UnexpiredVersions)
	if err != nil {
		return api.CredentialDetails{}, dbError(err)
	}
	d.EffectiveScopes = make([]string, 0, len(d.Credential.Scopes))
	allowed := make(map[string]bool, len(clientScopes))
	for _, scope := range clientScopes {
		allowed[scope] = true
	}
	for _, scope := range d.Credential.Scopes {
		if allowed[scope] {
			d.EffectiveScopes = append(d.EffectiveScopes, scope)
		}
	}
	return d, nil
}

// SecretVersions uses an exclusive generation cursor; zero starts at newest.
func (s *Store) SecretVersions(ctx context.Context, id string, before int64, limit int) ([]api.SecretVersionInfo, error) {
	if id == "" || before < 0 || limit < 1 || limit > 1000 {
		return nil, invalid("credential, nonnegative cursor and limit 1..1000 required")
	}
	query := `SELECT id,credential_id,generation,created_at,expires_at,last_used_at FROM ` + s.table("secret_versions") +
		` WHERE credential_id=$1 AND ($2::bigint=0 OR generation<$2) ORDER BY generation DESC LIMIT $3`
	rows, err := s.pool.Query(ctx, query, id, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]api.SecretVersionInfo, 0)
	for rows.Next() {
		var v api.SecretVersionInfo
		if err = rows.Scan(&v.ID, &v.CredentialID, &v.Generation, &v.CreatedAt, &v.ExpiresAt, &v.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) RetireVersion(ctx context.Context, credentialID, versionID string) error {
	if credentialID == "" || versionID == "" {
		return invalid("credential and version required")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		_, c, err := s.lockedCredential(ctx, tx, credentialID)
		if err != nil {
			return err
		}
		var generation int64
		query := `SELECT generation FROM ` + s.table("secret_versions") + ` WHERE id=$1 AND credential_id=$2 FOR UPDATE`
		if err = tx.QueryRow(ctx, query, versionID, credentialID).Scan(&generation); err != nil {
			return err
		}
		if generation >= c.Generation {
			return conflict("current version cannot be retired")
		}
		_, err = tx.Exec(ctx, `UPDATE `+s.table("secret_versions")+` SET expires_at=LEAST(expires_at,$2) WHERE id=$1`,
			versionID, time.Now().UTC())
		return err
	})
}

// RecordUsage bounds transaction work and acquires locks in global lexical
// client/credential/version order. Pruned or mismatched observations are ignored.
func (s *Store) RecordUsage(ctx context.Context, observations []api.UsageObservation) error {
	if len(observations) > 1000 {
		return invalid("at most 1000 usage observations required")
	}
	for _, o := range observations {
		if o.ClientID == "" || o.CredentialID == "" || o.VersionID == "" || o.At.IsZero() {
			return invalid("complete usage observation required")
		}
	}
	batch := append([]api.UsageObservation(nil), observations...)
	sort.Slice(batch, func(i, j int) bool {
		a, b := batch[i], batch[j]
		if a.ClientID != b.ClientID {
			return a.ClientID < b.ClientID
		}
		if a.CredentialID != b.CredentialID {
			return a.CredentialID < b.CredentialID
		}
		return a.VersionID < b.VersionID
	})
	if len(batch) == 0 {
		return nil
	}
	return s.atomic(ctx, false, func(tx pgx.Tx) error {
		for _, o := range batch {
			if err := s.recordUsage(ctx, tx, o); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) recordUsage(ctx context.Context, tx pgx.Tx, o api.UsageObservation) error {
	if _, err := s.lockClient(ctx, tx, o.ClientID); err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return nil
		}
		return err
	}
	var id string
	credentialSQL := `SELECT id FROM ` + s.table("credentials") + ` WHERE id=$1 AND client_id=$2 FOR UPDATE`
	err := tx.QueryRow(ctx, credentialSQL, o.CredentialID, o.ClientID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	versionSQL := `SELECT id FROM ` + s.table("secret_versions") + ` WHERE id=$1 AND credential_id=$2 FOR UPDATE`
	err = tx.QueryRow(ctx, versionSQL, o.VersionID, o.CredentialID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	updateCredential := `UPDATE ` + s.table("credentials") + ` SET last_used_at=GREATEST(last_used_at,$2) WHERE id=$1`
	if _, err = tx.Exec(ctx, updateCredential, o.CredentialID, o.At); err != nil {
		return err
	}
	updateVersion := `UPDATE ` + s.table("secret_versions") + ` SET last_used_at=GREATEST(last_used_at,$2) WHERE id=$1`
	_, err = tx.Exec(ctx, updateVersion, o.VersionID, o.At)
	return err
}
