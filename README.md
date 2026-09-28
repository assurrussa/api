# api

[Русская версия](docs/README.ru.md)

Embeddable M2M access management for Go: API token issuance, rotation,
revocation, integration bans, and permission checks. Each project has its
own access source, PostgreSQL schema, and cache instances.

Go 1.27, toolchain 1.27.1. Tested PostgreSQL version: 18.6. Module:
`github.com/assurrussa/api`. User sessions, OAuth, an administrative
HTTP API, and a `goadmin` interface are outside the scope of the first version.

## Installation and license

Specify an exact published version:

```sh
go get github.com/assurrussa/api@v0.1.0
```

License: [MIT](LICENSE). Supported import paths: the root package
`github.com/assurrussa/api`, `postgres`, `httpapi`, `cache/arc`, and `cache/rcu`
under the same prefix. Versions `v0.x` allow refinements to the public API
before the compatibility commitments of `v1`; contract changes are described in release notes.

## Access model

- `Client`: a service or integration, its state, and its allowed scopes.
- `Credential`: a named client credential with a permanent ID and its own
  scopes. One client can have several independent credentials.
- `SecretVersion`: a secret version with a mandatory expiration time. Rotation
  preserves the Credential, replaces the secret, and increments the generation.
- `Principal`: verified identifiers and the intersection of the client's and
  Credential's scopes. The host project checks ownership of orders, files,
  and other objects.

Scopes are exact strings, with no wildcards or role inheritance. The catalog
is defined through `Config.Scopes`; an empty set allows authentication, but not
operations that require scopes. Middleware requires all listed scopes.
The catalog restricts new administrative assignments. Changing the configured
catalog does not revoke permissions already stored: to revoke them, change the
client's scopes through `SetClientScopes` or revoke the Credential. During a
rollout with mixed configuration versions, this rule applies equally to all replicas.

Tokens contain 256 random bits and are opaque to clients. The database and caches
store SHA-256 verification values of random secrets. Secret comparison is
constant-time. The full token is returned only through `Issued` at issuance
and rotation; it cannot be recovered or displayed again.
Do not log `Issued.Token`, Authorization, or issuance response bodies.

`DefaultTTL` and `MaxTTL` are mandatory and set by the project. A zero operation
TTL uses DefaultTTL; values above MaxTTL are rejected. Tokens cannot be permanent.
The PostgreSQL Store sets the issuance time and grace start after acquiring the
required locks; `Issued.ExpiresAt` contains the expiration time actually stored.
External Store implementations can implement the optional `TimedStore` for the same semantics.
A slow write or commit still consumes part of TTL/grace before the response;
choose durations with enough margin for the operation budget.
An expired Credential can be renewed through administrative rotation if it has
not been revoked and the client is not banned.

Rotation accepts `ExpectedGeneration` to protect against concurrent replacements
and `GracePeriod` for the transition. Zero invalidates the previously current
secret. A positive period is capped by that secret's original expiration time.
Repeated rotations do not extend previously assigned transition deadlines;
several unexpired transition versions may remain valid at the same time.

A ban is reversible: after unbanning, valid, unrevoked credentials work again.
Credential revocation is irreversible and covers all of its versions. `RevokeAll`
revokes all existing client credentials; subsequent issuance of new credentials
is allowed. In a compromise, combine a ban with revocation if you also need to
prevent new issuance. Requests already admitted are not canceled retroactively.

## Integration

The project owns the database pool, configuration, migration execution, TLS,
rate limiting, and administrative authorization. All Service management methods
are a trusted Go API; there is no public issuance route using an ordinary bearer token.

```go
store, err := postgres.New(pool, "orders_access")
if err != nil { return err }

// Call in an explicit migration step, not on every web replica startup.
if err := store.Migrate(ctx); err != nil { return err }

service, err := api.New(store, api.Config{
    Scopes:     []string{"orders:read", "orders:write"},
    DefaultTTL: 24 * time.Hour,
    MaxTTL:     30 * 24 * time.Hour,
})
if err != nil { return err }
defer service.Close()

// Start is optional in strict mode; for caches, it starts their lifecycle.
if err := service.Start(ctx); err != nil { return err }

mux.Handle("GET /orders",
    httpapi.Middleware(service, "orders:read")(ordersHandler))
```

Supported imports: the root `api` package, `postgres`, `httpapi`, `cache/arc`, and
`cache/rcu`. Public Store/Source/Cache interfaces support custom adapters;
consistency contracts are documented in the interfaces' Go doc. Caches return
data to a shared validator and do not grant permissions themselves.

`New` does not access the network or start goroutines. `Start` is called once;
canceling its context stops service operation. `Close` is idempotent,
cancels and waits for workers and operations, including an unfinished Start.
The Service cannot be restarted after Close. Finish incoming HTTP requests
first, then close the Service and database pool. `Errors()` also exposes
rate-limited reports of LISTEN failures and background RCU refresh failures;
the channel is not a counter of every attempt.

Each project uses a separate schema. The schema name is passed explicitly to
`postgres.New`; names with the `pg_` prefix are forbidden. Migrations are embedded
in the adapter, versioned, and applied transactionally under an advisory lock.
All verifier reads must go to the primary; a pool with read replicas whose lag
is unbounded does not satisfy the contract. State writes go through Store/Service.

Administrative methods: `CreateClient`, `Client`, `Clients`, `SetClientScopes`,
`SetClientBanned`, `Issue`, `Rotate`, `Credential`, `Credentials`, `Revoke`,
`RevokeAll`. Lists use ID-based keyset pagination with `after` and a limit of
1–1000. For `goadmin`, wrap these methods in its administrative authorization;
business tokens do not replace operator authorization.

PostgreSQL retains secret version history. For the retention period chosen by
the project, call `Store.PruneExpiredVersions(ctx, cutoff, batchSize)` from an
administrative job in repeated small batches. The method deletes only expired
historical versions; it preserves the current Credential version even after
expiration so that administrative rotation remains possible. Define the audit
retention period before enabling cleanup.

## Strict verification, ARC, and RCU

By default, every request reads consistent state from PostgreSQL.
A new verification after confirmed revocation observes it. A storage error
does not grant access.

Enable caching explicitly:

```go
// Up to 10,000 frequently used entries, with at most 10 seconds of staleness.
api.WithCache(arc.Factory(10_000), 10*time.Second)

// Full projection: refresh every 30 seconds, with at most 2 minutes of staleness.
api.WithCache(rcu.Factory(30*time.Second), 2*time.Minute)

// Same interval, with a separate 60-second budget for initial and background loads.
api.WithCache(rcu.FactoryWithTimeout(30*time.Second, 60*time.Second), 2*time.Minute)
```

These are options for `api.New`. One adapter is selected at a time; if several
WithCache options are supplied, the last one applies. Uses `gocache v0.2.1`.

- ARC limits capacity and loads entries on a miss. TTL jitter is disabled.
- RCU loads a complete immutable snapshot; the refresh interval must be
  positive and below MaxStaleness. For compatibility, `Factory` also uses
  that interval as the load timeout; `FactoryWithTimeout` sets a separate
  positive timeout below MaxStaleness. After a failure, the scheduler delays
  event-driven and periodic retries using backoff with jitter, without losing
  one pending invalidation. An initial load failure aborts Start.
- MaxStaleness is set by the project and can be seconds or minutes.
  Age is measured from the start of the read, not from publication to the cache.
- Cache hits, TTL refreshes, and notifications do not extend trust in the data.
  Stale state requires a primary read; a failure returns an infrastructure error.
  Secret expiration is checked independently of cache expiration.
- Local invalidation increments the generation. Old loads and snapshots cannot
  grant access after a change has already been processed.

Changes send PostgreSQL NOTIFY transactionally. Each cached Service opens
**one additional dedicated connection** for LISTEN, outside the MaxConns limit
of the supplied pool. Its `BeforeConnect` and `AfterConnect` also apply to LISTEN.
The projection is invalidated when the connection is restored. Notifications
are best-effort: a missed event is bounded by MaxStaleness, rather than a promise
of immediate revocation. Strict mode does not open a listener.

In the first version, any change invalidates the entire local projection. ARC
then loads entries as needed, while RCU rebuilds its snapshot.
An unknown token in a fresh RCU snapshot does not trigger a full reload;
negative responses are not cached. Frequent changes can eliminate the benefit
of caching. The application must limit incoming invalid tokens; the package
is not a rate limiter.

HTTP accepts exactly one `Authorization: Bearer …` header. Tokens from URLs,
cookies, or request bodies are not supported. Responses: 401 for invalid access,
403 for insufficient scopes, and 503 when reliable verification is impossible.
Responses do not expose internal database errors or ban details.

## Working example

Use a separate local database; `sslmode=disable` below is intended only for
the local example. External APIs must be served over HTTPS.

```sh
export API_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/DATABASE?sslmode=disable'
export API_SCHEMA='api_demo'
go run ./examples/access migrate
go run ./examples/access create-client -name warehouse -scopes orders:read
go run ./examples/access issue -client CLIENT_ID -name reader -scopes orders:read -ttl 24h
go run ./examples/access serve -cache arc -max-staleness 10s
```

For RCU, the example accepts `-refresh` and `-snapshot-timeout`. A zero
`-snapshot-timeout` preserves the previous mode, where the load budget equals
`-refresh`; with a separate timeout, both values must be below
`-max-staleness`.

Save the issued token in the integration's secret store. The example returns it
in JSON only once. `GET /orders` checks `orders:read` and returns the Principal.
There are no administrative HTTP endpoints; the default bind address is `127.0.0.1:8080`.

```sh
go run ./examples/access rotate -credential CREDENTIAL_ID -generation 1 -grace 10m
go run ./examples/access ban -client CLIENT_ID
go run ./examples/access unban -client CLIENT_ID
go run ./examples/access revoke -credential CREDENTIAL_ID
go run ./examples/access revoke-all -client CLIENT_ID
go run ./examples/access scopes -client CLIENT_ID -scopes orders:read
go run ./examples/access clients -limit 100
go run ./examples/access credentials -client CLIENT_ID -limit 100
```

The example's TTL policy is 24 hours by default, with a maximum of 30 days.
This is example configuration, not hidden library defaults. If the issuance
response is lost after commit, the secret cannot be recovered: rotate the
corresponding credential, or revoke it and issue a new one. Lists return
metadata, without secrets or hashes.

## Checks

Requires the `golangci-lint` version from `.golangci-lint-version` (2.13.1).
The gate and `make lint` / `make lint-fix` check for an exact version match:
they first use `bin/golangci-lint`, then the binary from `PATH`. To install
the pinned official binary from the repository root:

```sh
api_lint_version=$(cat .golangci-lint-version)
api_lint_installer=$(mktemp)
curl -fsSL "https://raw.githubusercontent.com/golangci/golangci-lint/v${api_lint_version}/install.sh" -o "$api_lint_installer"
sh "$api_lint_installer" -b ./bin "v${api_lint_version}"
rm "$api_lint_installer"
bash scripts/lint.sh version
```

The installer verifies the release archive checksum. Regular checks use the
installed binary without downloading it again.

```sh
make check
```

The gate checks release-script regressions, the pinned `golangci-lint`, formatting,
vet, all race tests with PostgreSQL, the external consumer probe, and process E2E.
If `API_TEST_DATABASE_URL` is not set,
the script starts an isolated `postgres:18.6-alpine` container with a temporary port
and removes it after the check. With an explicit URL, use a dedicated test database:
tests create and remove only their own unique schemas.

`make unit` without a URL skips PostgreSQL tests and does not replace `make check`.
The GitHub workflow installs the same `golangci-lint` version, runs the full
gate and pinned `govulncheck` for PRs targeting
`main` and pushes to `main`; separately, it runs a one-minute token parser fuzz
test once a week. Required merge status is configured in branch settings.
The consumer probe uses a temporary module with a local `replace`; it proves
the public surface of the current checkout. To check a published version:

```sh
make consumer-release API_VERSION=v0.1.0
```

Requires Git and curl. For tagged versions, the command first checks the tag in
the public Git repository. An unpublished tag fails immediately, before querying
Go services. Canonical pseudo-versions remain supported for pre-tag checks.

The command automatically waits for the version's metadata, manifest, archive,
and checksum record to become available in the public Go services. It uses
lightweight HEAD requests, reports progress, and honors cache lifetimes and
`Retry-After`. The wait is bounded to 35 minutes by default; set
`API_RELEASE_WAIT_TIMEOUT` to a limit in seconds (1..86400) to change it.
An early request made before a tag exists can leave a
[cached 404 for up to 30 minutes](https://proxy.golang.org/).
Only after availability is confirmed does the clean consumer probe start.
Checksum, compatibility, and test failures stop immediately rather than being retried.

This command uses Go 1.27.1, a separate temporary module, and a fresh dependency
cache, and disables the workspace, local Go settings, and private module overrides.
Downloads use `proxy.golang.org` with verification through `sum.golang.org`.
The probe checks the exact version, absence of active replacements in the consumer
graph and `replace` directives in `api`'s downloaded `go.mod`, checksums,
supported imports, Service creation in strict, ARC, and RCU modes, tests,
and builds. `go list -m all` does not show directives inside dependencies: Go
ignores them. The published manifest is therefore read separately through
`go mod edit -json` without changing the file. Access to public Go services is required;
`latest`, branch names, and an empty version are rejected. The temporary module
and its cache are removed on exit.

### Releasing a version

1. Prepare changes on a branch and run `make check`. Create a PR targeting
   `main`, complete the required review, and wait for green CI after merge.
2. Before publishing the tag, check the release probe against the exact canonical
   pseudo-version of the public commit, obtained through
   `go list -m -f '{{.Version}}' github.com/assurrussa/api@<commit-sha>`.
3. Create an annotated tag for the chosen version on the verified merge commit,
   publish it, and verify that it points to the correct commit.
4. Run `make consumer-release API_VERSION=<version>`. The command automatically
   waits for public Go services and then checks the version with a fresh cache.
   A timeout or a checksum, compatibility, or test failure stops the release.
5. After successful verification, publish a GitHub Release with the commit SHA,
   requirements, and checks actually performed.

Published Go versions are immutable: tags must not be moved or recreated.
Fixes to a published release receive a new version. The release probe
confirms external consumption of the module; a production pilot in a real
service is verified separately.

Process E2E can be run separately:

```sh
make e2e
```

Requires Go, Bash, and a working Docker installation. The script creates its own
PostgreSQL 18.6 instance with a temporary loopback port, builds the CLI with the
race detector, and starts two HTTP replicas for each mode: strict, ARC, and RCU.
`API_DATABASE_URL`, `API_SCHEMA`, `API_TEST_DATABASE_URL`, and the local demo file
do not determine the database used by this setup: E2E always uses its own
container. Tokens remain in test memory; the report contains scenario names
and results.

Checks cover issuance and administrative rejections, HTTP 200/401/403/503,
scope intersection, bans/unbans, rotation with zero and positive grace,
TTL and its independence from the cache, concurrent rotation, irreversible
revocation, `revoke-all` followed by issuance, pagination, and schema isolation.
Additional failures: authoritative state changes without NOTIFY, termination
of only the Service's own LISTEN backend, PostgreSQL shutdown, initial RCU
snapshot failure, and recovery of verification without restarting HTTP processes.

Waits are bounded by timeouts; HTTP processes are stopped during test cleanup.
The shell trap removes the container and its anonymous volume and terminates
remaining processes in the test run's process group, including after a
`go test` failure or timeout. E2E data is disposable. The check uses local HTTP;
TLS, an external reverse proxy, network partitions, and sustained load are
outside this suite. The [E2E matrix](docs/e2e.md) describes criteria and limits.

```sh
API_TEST_DATABASE_URL='postgres://…' make bench
```

Benchmarks use real PostgreSQL queries and 1/10/100 thousand credentials,
a working set of 128 tokens, ARC capacity of 1024, and one sequential stream.
They compare reads without changes and one mutation per 100 verifications.
The report includes mean time, sampled verification p50/p95, allocations,
database reads, and database snapshots. Mutation time is included in ns/op,
but not in sampled verification p50/p95.
`init-allocated-B` is the total allocation during initialization and warmup,
**not** retained heap/RSS. `BenchmarkPostgresSnapshot` measures the full database
load separately. This compares scenarios; it is not a production SLO or a
sustainable load limit. Measured results and limitations:
[benchmark report](docs/benchmarks.md).

The transitive dependency `golang.org/x/text` is pinned to v0.39.0 to fix
[GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970). Vulnerability checks must be
repeated when dependencies change. Token expiration requires synchronized
server clocks; the monotonic age of the local cache is unaffected by clock adjustments.
