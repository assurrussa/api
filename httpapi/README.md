# Optional request correlation

`Middleware` retains its existing authentication-only behavior. Hosts can opt in:

```go
handler := httpapi.RequestIDMiddleware(
    httpapi.Middleware(auth, "seo:read")(application),
)
```

The outer middleware accepts exactly one `X-Request-ID` containing 1–128 ASCII
letters, digits, `.`, `_` or `-`. Missing, empty, oversized, unsafe, duplicate or
comma-joined values are replaced with a cryptographically random ID. This never
rejects an otherwise valid request. The resolved ID is available through
`RequestID(r.Context())`, the downstream request header and the response header,
including authentication errors. Downstream handlers must preserve that response
header. Panic recovery belongs to the host.

Other HTTP adapters can use `ResolveRequestID(allHeaderValues)` and
`WithRequestID(ctx, id)` without introducing a framework dependency. Keep all
header values when resolving duplicates. Do not log rejected input. Hosts own
logging: use structured fields for the resolved ID, method, route template,
status and a fixed error code; do not dump headers, credentials, query strings,
bodies or raw transport errors. A syntactically safe ID is still untrusted and
must never be treated as identity, authorization or proof of uniqueness.

Outbound clients call `NewRequestID()` when creating each HTTP request, including
reads and each explicit retry. Do not propagate a parent request ID as the new
attempt ID. A logical mutation keeps its existing `Idempotency-Key`, payload,
hashes and conditional headers unchanged. Older receivers need not echo the ID.

The ID identifies one created HTTP request, **not every physical wire attempt**.
Go's transparent transport retries may reuse its header. Do not change transport
retry behavior merely for diagnostics. A receiver needing finer granularity may
generate a separate local log-only attempt ID for each received request, without
replacing the echoed correlation ID or adding it to the protocol/domain identity.

This policy is opt-in: adapters whose existing contract uses `X-Request-ID` as a
stable operation key (for example AutoReshenie) must retain that contract instead.
