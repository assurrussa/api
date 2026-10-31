ALTER TABLE credentials ADD COLUMN last_used_at timestamptz;
ALTER TABLE secret_versions ADD COLUMN last_used_at timestamptz;

-- Audit retention and operation receipts are independent from credential/version
-- retention. In particular, receipts intentionally have no foreign keys or TTL.
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_kind text NOT NULL CHECK (actor_kind IN ('human', 'service')),
    actor_id text NOT NULL,
    action text NOT NULL,
    client_id text NOT NULL DEFAULT '',
    credential_id text NOT NULL DEFAULT '',
    version_id text NOT NULL DEFAULT '',
    operation_id text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_occurred_at_id_idx ON audit_events(occurred_at,id);
CREATE TABLE operation_receipts (
    id text PRIMARY KEY,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    receipt jsonb NOT NULL
);
