package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/postgres"
)

const (
	auditFailureActorKind    = "service"
	auditFailureCredentialID = "existing"
	auditFailureIssueAction  = "credential.issue"
	auditFailureRotateAction = "credential.rotate"
)

type auditFailureFixture struct {
	store    *postgres.Store
	actor    api.Actor
	current  api.SecretVersion
	previous api.SecretVersion
	issue    api.Credential
	initial  api.SecretVersion
	next     api.SecretVersion
	spec     api.OperationSpec
}

func newAuditFailureFixture(t *testing.T) auditFailureFixture {
	t.Helper()
	s, ctx := testStore(t)
	f := auditFailureFixture{store: s, actor: api.Actor{Kind: auditFailureActorKind, ID: "rollback-operator"}}
	for _, id := range []string{"a", "other"} {
		if err := s.CreateClientAudited(ctx, f.actor, client(id, managedReadScope, "write")); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{auditFailureCredentialID, "sibling", "unrelated"} {
		clientID := "a"
		if id == "unrelated" {
			clientID = "other"
		}
		c, v := grant(clientID, id, managedReadScope)
		if err := s.IssueAudited(ctx, f.actor, c, v); err != nil {
			t.Fatal(err)
		}
		if id == auditFailureCredentialID {
			f.previous = v
		}
	}
	f.current = f.previous
	f.current.ID = "existing_v2"
	f.current.Generation = 2
	if _, err := s.RotateAudited(ctx, f.actor, auditFailureCredentialID, 1, f.current, 30*time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Lookup(ctx, f.current.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.current = stored.Secret
	f.issue, f.initial = grant("a", "new-credential", managedReadScope)
	f.next = f.current
	f.next.ID = "existing_v3"
	f.next.Generation = 3
	f.spec = api.OperationSpec{ID: "rollback-operation", Fingerprint: [32]byte{11}}
	return f
}

// Hash verification material before comparing snapshots so a failed assertion
// can never disclose a digest or operation fingerprint. All rows and metadata,
// including original expiry deadlines, usage and revocation, remain covered.
func auditFailureState(t *testing.T, f auditFailureFixture) string {
	t.Helper()
	query := `SELECT jsonb_build_object(
 'clients', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id),'[]') FROM ` + f.store.Table("clients") + ` c),
 'credentials', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id),'[]') FROM ` + f.store.Table("credentials") + ` c),
 'versions', (SELECT coalesce(jsonb_agg((to_jsonb(v)-'digest') ||
     jsonb_build_object('digest_hash',md5(encode(v.digest,'hex'))) ORDER BY v.id),'[]')
     FROM ` + f.store.Table("secret_versions") + ` v),
 'audits', (SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]') FROM ` + f.store.Table("audit_events") + ` a),
 'receipts', (SELECT coalesce(jsonb_agg((to_jsonb(r)-'fingerprint') ||
     jsonb_build_object('fingerprint_hash',md5(encode(r.fingerprint,'hex'))) ORDER BY r.id),'[]')
     FROM ` + f.store.Table("operation_receipts") + ` r))::text`
	var state string
	if err := f.store.Pool().QueryRow(t.Context(), query).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func auditFailureListener(t *testing.T, f auditFailureFixture) *pgxpool.Conn {
	t.Helper()
	listener, err := f.store.Pool().Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(listener.Release)
	if _, err = listener.Exec(t.Context(), `LISTEN `+pgx.Identifier{f.store.Channel()}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	return listener
}

func assertAuditFailureUnchanged(t *testing.T, f auditFailureFixture, before string, listener *pgxpool.Conn) {
	t.Helper()
	if after := auditFailureState(t, f); after != before {
		t.Fatal("failed operation changed clients, credentials, secret versions, audits or receipts")
	}
	if _, err := f.store.Operation(t.Context(), f.spec.ID); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("failed operation left a receipt: %v", err)
	}
	// PostgreSQL delivers notifications in commit order. A marker committed
	// after the failed call must arrive first if the rollback emitted nothing.
	const marker = "rollback-check-complete"
	if _, err := f.store.Pool().Exec(t.Context(), `SELECT pg_notify($1,$2)`, f.store.Channel(), marker); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	notification, err := listener.Conn().WaitForNotification(wait)
	if err != nil {
		t.Fatalf("notification barrier: %v", err)
	}
	if notification.Payload != marker {
		t.Fatalf("failed operation emitted notification %q", notification.Payload)
	}
}

type auditedFailureCase struct {
	name   string
	action string
	mutate func(context.Context, auditFailureFixture, api.Actor) error
}

func auditedFailureCases() []auditedFailureCase {
	return []auditedFailureCase{
		{"create_client", "client.create", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.CreateClientAudited(ctx, a, client("new-client", managedReadScope))
		}},
		{"set_scopes", "client.scopes", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.SetClientScopesAudited(ctx, a, "a", []string{managedReadScope})
		}},
		{"set_banned", "client.ban", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.SetClientBannedAudited(ctx, a, "a", true)
		}},
		{"issue", auditFailureIssueAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.IssueAudited(ctx, a, f.issue, f.initial)
		}},
		{"rotate", auditFailureRotateAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			_, err := f.store.RotateAudited(ctx, a, auditFailureCredentialID, 2, f.next, time.Minute, time.Now())
			return err
		}},
		{"revoke", "credential.revoke", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.RevokeAudited(ctx, a, auditFailureCredentialID, time.Now())
		}},
		{"revoke_all", "client.revoke_all", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.RevokeAllAudited(ctx, a, "a", time.Now())
		}},
		{"timed_issue", auditFailureIssueAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			_, _, err := f.store.IssueWithLifetimeAudited(ctx, a, f.issue, f.initial, time.Hour)
			return err
		}},
		{"timed_rotate", auditFailureRotateAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			_, _, err := f.store.RotateWithLifetimeAudited(ctx, a, auditFailureCredentialID, 2, f.next, time.Hour, time.Minute)
			return err
		}},
		{"retire_version", "version.retire", func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			return f.store.RetireVersionAudited(ctx, a, auditFailureCredentialID, f.previous.ID)
		}},
		{"issue_once", auditFailureIssueAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			_, _, err := f.store.IssueOnceAudited(ctx, a, f.spec, f.issue, f.initial, time.Hour)
			return err
		}},
		{"rotate_once", auditFailureRotateAction, func(ctx context.Context, f auditFailureFixture, a api.Actor) error {
			_, _, err := f.store.RotateOnceAudited(ctx, a, f.spec, auditFailureCredentialID, 2, f.next, time.Hour, time.Minute)
			return err
		}},
	}
}

func TestAuditedMutationFailureMatrix(t *testing.T) {
	for _, tc := range auditedFailureCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFailureFixture(t)
			// Actions are fixed test literals; use a quoted SQL string, not an identifier.
			query := fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT reject_test_audit CHECK (action <> '%s') NOT VALID`,
				f.store.Table("audit_events"), tc.action)
			if _, err := f.store.Pool().Exec(t.Context(), query); err != nil {
				t.Fatal(err)
			}
			before := auditFailureState(t, f)
			listener := auditFailureListener(t, f)
			assertInjectedConstraint(t, tc.mutate(t.Context(), f, f.actor), "reject_test_audit")
			assertAuditFailureUnchanged(t, f, before, listener)
		})
	}
}

func TestAuditedMutationMissingActorMatrix(t *testing.T) {
	for _, tc := range auditedFailureCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFailureFixture(t)
			before := auditFailureState(t, f)
			listener := auditFailureListener(t, f)
			if err := tc.mutate(t.Context(), f, api.Actor{}); !errors.Is(err, api.ErrInvalid) {
				t.Fatalf("missing actor: %v", err)
			}
			assertAuditFailureUnchanged(t, f, before, listener)
		})
	}
}

func assertInjectedConstraint(t *testing.T, err error, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
		t.Fatalf("expected injected constraint %q, got %v", constraint, err)
	}
}

func rejectReceiptAfterMutationAndAudit(t *testing.T, f auditFailureFixture, rotate bool) {
	t.Helper()
	credentialID, versionID, generation := f.issue.ID, f.initial.ID, int64(1)
	oldVersionCheck := "true"
	if rotate {
		credentialID, versionID, generation = auditFailureCredentialID, f.next.ID, f.next.Generation
		oldVersionCheck = fmt.Sprintf(`EXISTS (SELECT 1 FROM %s WHERE id='existing_v2' AND expires_at < '%s'::timestamptz)`,
			f.store.Table("secret_versions"), f.current.ExpiresAt.Format(time.RFC3339Nano))
	}
	query := fmt.Sprintf(`CREATE FUNCTION %s.reject_test_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
   IF NOT EXISTS (SELECT 1 FROM %s c JOIN %s v ON v.credential_id=c.id
       WHERE c.id='%s' AND c.generation=%d AND v.id='%s' AND v.generation=%d)
     OR NOT EXISTS (SELECT 1 FROM %s WHERE operation_id=NEW.id AND credential_id='%s' AND version_id='%s')
     OR NOT (%s) THEN
     RAISE EXCEPTION 'receipt insertion did not observe pending mutation and audit';
   END IF;
   RAISE EXCEPTION 'injected receipt failure' USING ERRCODE='23514', CONSTRAINT='reject_test_receipt';
 END $$;
 CREATE TRIGGER reject_test_receipt BEFORE INSERT ON %s
 FOR EACH ROW EXECUTE FUNCTION %s.reject_test_receipt()`,
		f.store.QuotedSchema(), f.store.Table("credentials"), f.store.Table("secret_versions"),
		credentialID, generation, versionID, generation, f.store.Table("audit_events"), credentialID, versionID,
		oldVersionCheck, f.store.Table("operation_receipts"), f.store.QuotedSchema())
	if _, err := f.store.Pool().Exec(t.Context(), query); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptFailureRollsBackMutationAndAudit(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "issue_once"
		if rotate {
			name = "rotate_once"
		}
		t.Run(name, func(t *testing.T) {
			f := newAuditFailureFixture(t)
			rejectReceiptAfterMutationAndAudit(t, f, rotate)
			before := auditFailureState(t, f)
			listener := auditFailureListener(t, f)
			var receipt api.OperationReceipt
			var applied bool
			var err error
			if rotate {
				receipt, applied, err = f.store.RotateOnceAudited(t.Context(), f.actor, f.spec, auditFailureCredentialID, 2,
					f.next, time.Hour, time.Minute)
			} else {
				receipt, applied, err = f.store.IssueOnceAudited(t.Context(), f.actor, f.spec, f.issue, f.initial, time.Hour)
			}
			assertInjectedConstraint(t, err, "reject_test_receipt")
			if applied || receipt.ID != "" || receipt.Credential.ID != "" || receipt.Version.ID != "" {
				t.Fatal("failed receipt insertion returned an applied operation or partial receipt")
			}
			assertAuditFailureUnchanged(t, f, before, listener)
		})
	}
}
