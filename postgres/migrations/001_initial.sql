CREATE TABLE clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    scopes text[] NOT NULL,
    banned boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL
);

CREATE TABLE credentials (
    id text PRIMARY KEY,
    client_id text NOT NULL REFERENCES clients(id),
    name text NOT NULL,
    scopes text[] NOT NULL,
    generation bigint NOT NULL CHECK (generation >= 1),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL
);
CREATE INDEX credentials_client_id_id_idx ON credentials(client_id, id);

CREATE TABLE secret_versions (
    id text PRIMARY KEY,
    credential_id text NOT NULL REFERENCES credentials(id),
    generation bigint NOT NULL CHECK (generation >= 1),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (credential_id, generation)
);
CREATE INDEX secret_versions_credential_id_idx ON secret_versions(credential_id);
