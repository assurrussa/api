#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/api-consumer-probe.XXXXXX")"
trap 'rm -rf "$probe_dir"' EXIT

cat > "$probe_dir/go.mod" <<'EOF'
module api-consumer-probe

go 1.27.0

require github.com/assurrussa/api v0.0.0
EOF
(
  cd "$probe_dir"
  GOWORK=off go mod edit "-replace=github.com/assurrussa/api=$repo_root"
)
cat > "$probe_dir/consumer_test.go" <<'EOF'
package consumerprobe

import (
	"context"
	"net/http"
	"testing"
	"time"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/assurrussa/api/httpapi"
	"github.com/assurrussa/api/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ api.Store = (*postgres.Store)(nil)
var _ api.Watcher = (*postgres.Store)(nil)
var _ http.Handler = httpapi.Middleware(nil, "orders:read")(http.HandlerFunc(func(http.ResponseWriter,*http.Request){}))

func TestPublicConstruction(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgres://probe:example@localhost/probe")
	if err != nil { t.Fatal(err) }
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil { t.Fatal(err) }
	defer pool.Close()
	store, err := postgres.New(pool,"probe_schema")
	if err != nil { t.Fatal(err) }
	cfg := api.Config{Scopes:[]string{"orders:read"},DefaultTTL:time.Hour,MaxTTL:24*time.Hour}
	for _, option := range []api.Option{api.WithCache(arc.Factory(100),time.Minute),api.WithCache(rcu.Factory(5*time.Second),time.Minute)} {
		service, err := api.New(store,cfg,option)
		if err != nil { t.Fatal(err) }
		if err := service.Close(); err != nil { t.Fatal(err) }
	}
}
EOF
(
  cd "$probe_dir"
  GOWORK=off go mod tidy
  GOWORK=off go test ./...
  GOWORK=off go build ./...
)
printf '%s\n' 'Local consumer probe passed (temporary module with local replace; not published-version evidence).'
