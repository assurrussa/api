// Package postgres provides the PostgreSQL authority for api credentials.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	api "github.com/assurrussa/api"
)

//go:embed migrations/*.sql
var migrations embed.FS

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

const rollbackTimeout = 5 * time.Second

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	// pgx closes a connection whose rollback fails, including on timeout.
	_ = tx.Rollback(ctx)
}

type Store struct {
	pool    *pgxpool.Pool
	schema  string
	q       string
	channel string
}

var (
	_ api.Store      = (*Store)(nil)
	_ api.Watcher    = (*Store)(nil)
	_ api.TimedStore = (*Store)(nil)
)

// New does not touch the database. The caller owns pool and must call Migrate.
func New(pool *pgxpool.Pool, schema string) (*Store, error) {
	if pool == nil || !schemaName.MatchString(schema) || strings.HasPrefix(schema, "pg_") {
		return nil, fmt.Errorf("%w: pool and safe schema required", api.ErrInvalid)
	}
	h := sha256.Sum256([]byte(schema))
	return &Store{pool: pool, schema: schema, q: pgx.Identifier{schema}.Sanitize(), channel: fmt.Sprintf("api_m2m_%x", h[:12])}, nil
}

func (s *Store) table(name string) string { return s.q + "." + name }

// Migrate applies numbered, embedded migrations under a transaction-scoped lock.
func (s *Store) Migrate(ctx context.Context) error {
	// A waiter must see migrations committed by the previous lock holder.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	//nolint:contextcheck // Rollback in defer intentionally uses a detached background timeout.
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(723901, hashtext($1))`, s.schema); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+s.q); err != nil {
		return err
	}
	createTableSQL := `CREATE TABLE IF NOT EXISTS ` + s.table("schema_migrations") +
		` (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`
	if _, err = tx.Exec(ctx, createTableSQL); err != nil {
		return err
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return err
		}
		var applied bool
		existsSQL := `SELECT EXISTS(SELECT 1 FROM ` + s.table("schema_migrations") + ` WHERE version=$1)`
		if err = tx.QueryRow(ctx, existsSQL, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SET LOCAL search_path TO `+s.q); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO `+s.table("schema_migrations")+`(version) VALUES($1)`, version); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %w", api.ErrNotFound, err)
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return fmt.Errorf("%w: %w", api.ErrConflict, err)
		case "23503", "23514", "23502", "22001":
			return fmt.Errorf("%w: %w", api.ErrInvalid, err)
		}
	}
	return err
}

func invalid(message string) error   { return fmt.Errorf("%w: %s", api.ErrInvalid, message) }
func conflict(message string) error  { return fmt.Errorf("%w: %s", api.ErrConflict, message) }
func forbidden(message string) error { return fmt.Errorf("%w: %s", api.ErrForbidden, message) }

func scopesSubset(requested, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		set[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

func cloneScopes(scopes []string) []string { return append([]string{}, scopes...) }

func (s *Store) transaction(ctx context.Context, f func(pgx.Tx) error) error {
	// Statements after a lock wait must see commits made during that wait.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	//nolint:contextcheck // Rollback in defer intentionally uses a detached background timeout.
	defer rollback(tx)
	if err = f(tx); err != nil {
		return dbError(err)
	}
	if _, err = tx.Exec(ctx, `SELECT pg_notify($1, 'changed')`, s.channel); err != nil {
		return err
	}
	return dbError(tx.Commit(ctx))
}

func (s *Store) lockClient(ctx context.Context, tx pgx.Tx, id string) (api.Client, error) {
	var c api.Client
	query := `SELECT id,name,scopes,banned,created_at FROM ` + s.table("clients") + ` WHERE id=$1 FOR UPDATE`
	err := tx.QueryRow(ctx, query, id).Scan(&c.ID, &c.Name, &c.Scopes, &c.Banned, &c.CreatedAt)
	return c, dbError(err)
}

func (s *Store) credential(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, id string, forUpdate bool,
) (api.Credential, error) {
	var c api.Credential
	sql := `SELECT id,client_id,name,scopes,generation,revoked_at,created_at FROM ` + s.table("credentials") + ` WHERE id=$1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, id).Scan(&c.ID, &c.ClientID, &c.Name, &c.Scopes, &c.Generation, &c.RevokedAt, &c.CreatedAt)
	return c, dbError(err)
}

func (s *Store) CreateClient(ctx context.Context, c api.Client) error {
	if c.ID == "" || c.Name == "" {
		return invalid("client id and name required")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		query := `INSERT INTO ` + s.table("clients") + `(id,name,scopes,banned,created_at) VALUES($1,$2,$3,$4,$5)`
		_, err := tx.Exec(ctx, query, c.ID, c.Name, cloneScopes(c.Scopes), c.Banned, c.CreatedAt)
		return err
	})
}

func (s *Store) Client(ctx context.Context, id string) (api.Client, error) {
	var c api.Client
	query := `SELECT id,name,scopes,banned,created_at FROM ` + s.table("clients") + ` WHERE id=$1`
	err := s.pool.QueryRow(ctx, query, id).Scan(&c.ID, &c.Name, &c.Scopes, &c.Banned, &c.CreatedAt)
	return c, dbError(err)
}

func (s *Store) Clients(ctx context.Context, after string, limit int) ([]api.Client, error) {
	if limit < 1 || limit > 1000 {
		return nil, invalid("limit must be 1..1000")
	}
	query := `SELECT id,name,scopes,banned,created_at FROM ` + s.table("clients") + ` WHERE id>$1 ORDER BY id LIMIT $2`
	rows, err := s.pool.Query(ctx, query, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]api.Client, 0)
	for rows.Next() {
		var c api.Client
		if err = rows.Scan(&c.ID, &c.Name, &c.Scopes, &c.Banned, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SetClientScopes(ctx context.Context, id string, scopes []string) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockClient(ctx, tx, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE `+s.table("clients")+` SET scopes=$2 WHERE id=$1`, id, cloneScopes(scopes))
		return err
	})
}

func (s *Store) SetClientBanned(ctx context.Context, id string, banned bool) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockClient(ctx, tx, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE `+s.table("clients")+` SET banned=$2 WHERE id=$1`, id, banned)
		return err
	})
}

func (s *Store) Issue(ctx context.Context, c api.Credential, v api.SecretVersion) error {
	_, _, err := s.issue(ctx, c, v, 0)
	return err
}

func (s *Store) IssueWithLifetime(
	ctx context.Context, c api.Credential, v api.SecretVersion, ttl time.Duration,
) (api.Credential, api.SecretVersion, error) {
	if ttl <= 0 {
		return api.Credential{}, api.SecretVersion{}, invalid("positive lifetime required")
	}
	return s.issue(ctx, c, v, ttl)
}

func (s *Store) issue(
	ctx context.Context, c api.Credential, v api.SecretVersion, ttl time.Duration,
) (api.Credential, api.SecretVersion, error) {
	if c.ID == "" || c.ClientID == "" || v.ID == "" || v.CredentialID != c.ID ||
		c.Generation != 1 || v.Generation != 1 || c.RevokedAt != nil || v.ExpiresAt.IsZero() {
		return api.Credential{}, api.SecretVersion{}, invalid("invalid initial credential or secret version")
	}
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		client, err := s.lockClient(ctx, tx, c.ClientID)
		if err != nil {
			return err
		}
		if client.Banned {
			return forbidden("client banned")
		}
		if !scopesSubset(c.Scopes, client.Scopes) {
			return forbidden("credential scopes exceed client scopes")
		}
		if ttl > 0 {
			at := time.Now().UTC()
			c.CreatedAt = at
			v.CreatedAt = at
			v.ExpiresAt = at.Add(ttl)
		}
		queryCred := `INSERT INTO ` + s.table("credentials") +
			`(id,client_id,name,scopes,generation,revoked_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`
		_, err = tx.Exec(ctx, queryCred, c.ID, c.ClientID, c.Name, cloneScopes(c.Scopes), c.Generation, c.RevokedAt, c.CreatedAt)
		if err != nil {
			return err
		}
		querySec := `INSERT INTO ` + s.table("secret_versions") +
			`(id,credential_id,generation,digest,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)`
		_, err = tx.Exec(ctx, querySec, v.ID, v.CredentialID, v.Generation, v.Digest[:], v.ExpiresAt, v.CreatedAt)
		return err
	})
	if err != nil {
		return api.Credential{}, api.SecretVersion{}, err
	}
	return c, v, nil
}

func (s *Store) Credential(ctx context.Context, id string) (api.Credential, error) {
	return s.credential(ctx, s.pool, id, false)
}

func (s *Store) Credentials(ctx context.Context, clientID, after string, limit int) ([]api.Credential, error) {
	if limit < 1 || limit > 1000 {
		return nil, invalid("limit must be 1..1000")
	}
	query := `SELECT id,client_id,name,scopes,generation,revoked_at,created_at FROM ` +
		s.table("credentials") + ` WHERE client_id=$1 AND id>$2 ORDER BY id LIMIT $3`
	rows, err := s.pool.Query(ctx, query, clientID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]api.Credential, 0)
	for rows.Next() {
		var c api.Credential
		if err = rows.Scan(&c.ID, &c.ClientID, &c.Name, &c.Scopes, &c.Generation, &c.RevokedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Lock order for all credential mutations is client then credential.
func (s *Store) lockedCredential(ctx context.Context, tx pgx.Tx, id string) (api.Client, api.Credential, error) {
	var clientID string
	if err := tx.QueryRow(ctx, `SELECT client_id FROM `+s.table("credentials")+` WHERE id=$1`, id).Scan(&clientID); err != nil {
		return api.Client{}, api.Credential{}, dbError(err)
	}
	client, err := s.lockClient(ctx, tx, clientID)
	if err != nil {
		return api.Client{}, api.Credential{}, err
	}
	credential, err := s.credential(ctx, tx, id, true)
	return client, credential, err
}

func (s *Store) Rotate(
	ctx context.Context, id string, expected int64, v api.SecretVersion, grace time.Duration, at time.Time,
) (api.Credential, error) {
	credential, _, err := s.rotate(ctx, id, expected, v, 0, grace, at)
	return credential, err
}

func (s *Store) RotateWithLifetime(
	ctx context.Context, id string, expected int64, v api.SecretVersion, ttl, grace time.Duration,
) (api.Credential, api.SecretVersion, error) {
	if ttl <= 0 {
		return api.Credential{}, api.SecretVersion{}, invalid("positive lifetime required")
	}
	return s.rotate(ctx, id, expected, v, ttl, grace, v.CreatedAt)
}

func (s *Store) rotate(
	ctx context.Context, id string, expected int64, v api.SecretVersion, ttl, grace time.Duration, at time.Time,
) (api.Credential, api.SecretVersion, error) {
	if id == "" || v.ID == "" || v.CredentialID != id || expected < 1 ||
		v.Generation != expected+1 || grace < 0 || v.ExpiresAt.IsZero() || at.IsZero() {
		return api.Credential{}, api.SecretVersion{}, invalid("invalid rotation")
	}
	var result api.Credential
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		client, c, err := s.lockedCredential(ctx, tx, id)
		if err != nil {
			return err
		}
		if client.Banned {
			return forbidden("client banned")
		}
		if c.RevokedAt != nil {
			return conflict("credential revoked")
		}
		if c.Generation != expected {
			return conflict("generation changed")
		}
		if ttl > 0 {
			at = time.Now().UTC()
			v.CreatedAt = at
			v.ExpiresAt = at.Add(ttl)
		}
		deadline := at.Add(grace)
		queryExpire := `UPDATE ` + s.table("secret_versions") +
			` SET expires_at=LEAST(expires_at,$3) WHERE credential_id=$1 AND generation=$2`
		tag, err := tx.Exec(ctx, queryExpire, id, expected, deadline)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return conflict("current secret version missing")
		}
		queryInsertSec := `INSERT INTO ` + s.table("secret_versions") +
			`(id,credential_id,generation,digest,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)`
		_, err = tx.Exec(ctx, queryInsertSec, v.ID, id, v.Generation, v.Digest[:], v.ExpiresAt, v.CreatedAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE `+s.table("credentials")+` SET generation=$2 WHERE id=$1`, id, v.Generation)
		if err != nil {
			return err
		}
		c.Generation = v.Generation
		result = c
		return nil
	})
	if err != nil {
		return api.Credential{}, api.SecretVersion{}, err
	}
	return result, v, nil
}

func (s *Store) Revoke(ctx context.Context, id string, at time.Time) error {
	if id == "" || at.IsZero() {
		return invalid("credential id and time required")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		_, c, err := s.lockedCredential(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.RevokedAt != nil {
			return conflict("credential revoked")
		}
		_, err = tx.Exec(ctx, `UPDATE `+s.table("credentials")+` SET revoked_at=$2 WHERE id=$1`, id, at)
		return err
	})
}

func (s *Store) RevokeAll(ctx context.Context, clientID string, at time.Time) error {
	if clientID == "" || at.IsZero() {
		return invalid("client id and time required")
	}
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockClient(ctx, tx, clientID); err != nil {
			return err
		}
		query := `UPDATE ` + s.table("credentials") + ` SET revoked_at=$2 WHERE client_id=$1 AND revoked_at IS NULL`
		_, err := tx.Exec(ctx, query, clientID, at)
		return err
	})
}

const recordColumns = `c.id,c.name,c.scopes,c.banned,c.created_at,` +
	`k.id,k.client_id,k.name,k.scopes,k.generation,k.revoked_at,k.created_at,` +
	`v.id,v.credential_id,v.generation,v.digest,v.expires_at,v.created_at`

func scanRecord(row interface{ Scan(dest ...any) error }) (api.Record, error) {
	var r api.Record
	var digest []byte
	err := row.Scan(
		&r.Client.ID, &r.Client.Name, &r.Client.Scopes, &r.Client.Banned, &r.Client.CreatedAt,
		&r.Credential.ID, &r.Credential.ClientID, &r.Credential.Name, &r.Credential.Scopes,
		&r.Credential.Generation, &r.Credential.RevokedAt, &r.Credential.CreatedAt,
		&r.Secret.ID, &r.Secret.CredentialID, &r.Secret.Generation, &digest,
		&r.Secret.ExpiresAt, &r.Secret.CreatedAt,
	)
	if err != nil {
		return api.Record{}, dbError(err)
	}
	if len(digest) != 32 {
		return api.Record{}, fmt.Errorf("invalid stored digest length %d", len(digest))
	}
	copy(r.Secret.Digest[:], digest)
	return r, nil
}

func (s *Store) joined() string {
	return ` SELECT ` + recordColumns + ` FROM ` + s.table("secret_versions") +
		` v JOIN ` + s.table("credentials") + ` k ON k.id=v.credential_id JOIN ` +
		s.table("clients") + ` c ON c.id=k.client_id `
}

func (s *Store) Lookup(ctx context.Context, id string) (api.Record, error) {
	if id == "" {
		return api.Record{}, invalid("version id required")
	}
	return scanRecord(s.pool.QueryRow(ctx, s.joined()+` WHERE v.id=$1`, id))
}

func (s *Store) Snapshot(ctx context.Context) (map[string]api.Record, error) {
	rows, err := s.pool.Query(ctx, s.joined()+` WHERE k.revoked_at IS NULL AND v.expires_at>now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]api.Record)
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out[r.Secret.ID] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// PruneExpiredVersions deletes at most limit expired historical versions.
// The current generation is retained even after expiry so Rotate remains
// possible. Callers choose the retention cutoff and schedule this operation.
func (s *Store) PruneExpiredVersions(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || before.After(time.Now()) || limit < 1 || limit > 1000 {
		return 0, invalid("past cutoff and limit 1..1000 required")
	}
	var removed int64
	err := s.pool.QueryRow(ctx, `WITH candidates AS (
		SELECT v.id FROM `+s.table("secret_versions")+` v
		JOIN `+s.table("credentials")+` k ON k.id=v.credential_id
		WHERE v.expires_at < $1 AND v.generation < k.generation
		ORDER BY v.expires_at,v.id LIMIT $2 FOR UPDATE OF v SKIP LOCKED
	), deleted AS (
		DELETE FROM `+s.table("secret_versions")+` v USING candidates c WHERE v.id=c.id RETURNING v.id
	) SELECT count(*) FROM deleted`, before, limit).Scan(&removed)
	return removed, err
}
