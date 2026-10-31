package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	api "github.com/assurrussa/api"
)

var (
	_ api.OperationStore        = (*Store)(nil)
	_ api.AuditedOperationStore = (*Store)(nil)
)

func validOperationID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func (s *Store) operation(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, id string,
) (api.OperationReceipt, error) {
	var receipt api.OperationReceipt
	var body, fingerprint []byte
	query := `SELECT fingerprint,receipt FROM ` + s.table("operation_receipts") + ` WHERE id=$1`
	err := q.QueryRow(ctx, query, id).Scan(&fingerprint, &body)
	if err != nil {
		return api.OperationReceipt{}, dbError(err)
	}
	if err = json.Unmarshal(body, &receipt); err != nil {
		return api.OperationReceipt{}, err
	}
	if len(fingerprint) != sha256.Size {
		return api.OperationReceipt{}, invalid("invalid stored operation fingerprint")
	}
	copy(receipt.Fingerprint[:], fingerprint)
	return receipt, nil
}

func (s *Store) Operation(ctx context.Context, id string) (api.OperationReceipt, error) {
	if !validOperationID(id) {
		return api.OperationReceipt{}, invalid("operation id must be 1..128 printable ASCII characters")
	}
	return s.operation(ctx, s.pool, id)
}

func safeVersion(v api.SecretVersion) api.SecretVersionInfo {
	return api.SecretVersionInfo{
		ID: v.ID, CredentialID: v.CredentialID, Generation: v.Generation, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
	}
}

func (s *Store) once(
	ctx context.Context,
	a *api.Actor,
	spec api.OperationSpec,
	kind string,
	f func(*Store) (api.Credential, api.SecretVersion, error),
) (api.OperationReceipt, bool, error) {
	if !validOperationID(spec.ID) {
		return api.OperationReceipt{}, false, invalid("operation id must be 1..128 printable ASCII characters")
	}
	if a != nil && !a.Valid() {
		return api.OperationReceipt{}, false, invalid("verified human or service actor required")
	}
	var receipt api.OperationReceipt
	applied := false
	err := s.atomic(ctx, false, func(tx pgx.Tx) error {
		// Do not inherit a host's repeatable-read default: the post-lock read
		// must observe a receipt committed while this transaction was waiting.
		if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
			return err
		}
		// The operation lock must precede all client/credential/version locks. A
		// waiter rechecks the receipt in its next READ COMMITTED statement.
		key := sha256.Sum256([]byte(s.schema + "\x00" + spec.ID))
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(key[:8]))); err != nil {
			return err
		}
		previous, err := s.operation(ctx, tx, spec.ID)
		if err == nil {
			if previous.Fingerprint != spec.Fingerprint || previous.Kind != kind {
				return conflict("operation parameters changed")
			}
			receipt = previous
			return nil
		}
		if !errors.Is(err, api.ErrNotFound) {
			return err
		}
		c, v, err := f(s.bound(tx))
		if err != nil {
			return err
		}
		if a != nil {
			event := api.AuditEvent{
				Actor: *a, Action: "credential." + kind, ClientID: c.ClientID, CredentialID: c.ID, VersionID: v.ID, OperationID: spec.ID,
			}
			if err = s.appendAudit(ctx, tx, event); err != nil {
				return err
			}
		}
		receipt = api.OperationReceipt{
			ID: spec.ID, Fingerprint: spec.Fingerprint, Kind: kind, Credential: c,
			Version: safeVersion(v), CommittedAt: time.Now().UTC(),
		}
		body, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		query := `INSERT INTO ` + s.table("operation_receipts") + ` (id,fingerprint,receipt) VALUES($1,$2,$3)`
		if _, err = tx.Exec(ctx, query, spec.ID, spec.Fingerprint[:], body); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT pg_notify($1,'changed')`, s.channel); err != nil {
			return err
		}
		applied = true
		return nil
	})
	if err != nil {
		return api.OperationReceipt{}, false, err
	}
	return receipt, applied, nil
}

func (s *Store) IssueOnce(
	ctx context.Context,
	spec api.OperationSpec,
	c api.Credential,
	v api.SecretVersion,
	ttl time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.issueOnce(ctx, nil, spec, c, v, ttl)
}

func (s *Store) IssueOnceAudited(
	ctx context.Context,
	a api.Actor,
	spec api.OperationSpec,
	c api.Credential,
	v api.SecretVersion,
	ttl time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.issueOnce(ctx, &a, spec, c, v, ttl)
}

func (s *Store) issueOnce(
	ctx context.Context,
	a *api.Actor,
	spec api.OperationSpec,
	c api.Credential,
	v api.SecretVersion,
	ttl time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.once(ctx, a, spec, "issue", func(b *Store) (api.Credential, api.SecretVersion, error) {
		return b.IssueWithLifetime(ctx, c, v, ttl)
	})
}

func (s *Store) RotateOnce(
	ctx context.Context,
	spec api.OperationSpec,
	id string,
	expected int64,
	v api.SecretVersion,
	ttl, grace time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.rotateOnce(ctx, nil, spec, id, expected, v, ttl, grace)
}

func (s *Store) RotateOnceAudited(
	ctx context.Context,
	a api.Actor,
	spec api.OperationSpec,
	id string,
	expected int64,
	v api.SecretVersion,
	ttl, grace time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.rotateOnce(ctx, &a, spec, id, expected, v, ttl, grace)
}

func (s *Store) rotateOnce(
	ctx context.Context,
	a *api.Actor,
	spec api.OperationSpec,
	id string,
	expected int64,
	v api.SecretVersion,
	ttl, grace time.Duration,
) (api.OperationReceipt, bool, error) {
	return s.once(ctx, a, spec, "rotate", func(b *Store) (api.Credential, api.SecretVersion, error) {
		return b.RotateWithLifetime(ctx, id, expected, v, ttl, grace)
	})
}
