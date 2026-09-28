#!/usr/bin/env bash
set -euo pipefail

api_probe_version=''
if [ "$#" -ne 0 ]; then
  if [ "$#" -ne 2 ] || [ "$1" != '--version' ]; then
    printf '%s\n' 'Usage: consumer-probe.sh [--version vX.Y.Z[-prerelease]]' >&2
    exit 2
  fi
  api_probe_version="$2"
  api_version_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
  if [[ ! "$api_probe_version" =~ $api_version_pattern ]]; then
    printf '%s\n' 'An exact Go module version is required; branch names and latest are not accepted.' >&2
    exit 2
  fi
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/api-consumer-probe.XXXXXX")"
cleanup() {
  # Downloaded module directories are read-only by default.
  chmod -R u+w "$probe_dir"
  rm -rf "$probe_dir"
}
trap cleanup EXIT
module_dir="$probe_dir/consumer"
mkdir "$module_dir"

export GOWORK=off
if [ -n "$api_probe_version" ]; then
  export GOENV=off GO111MODULE=on GOFLAGS='' GOTOOLCHAIN=go1.27.1
  export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
  export GOPRIVATE='' GONOPROXY='' GONOSUMDB=''
  export GOMODCACHE="$probe_dir/module-cache"
fi

cat > "$module_dir/go.mod" <<EOF
module api-consumer-probe

go 1.27.0

require github.com/assurrussa/api ${api_probe_version:-v0.0.0}
EOF
if [ -z "$api_probe_version" ]; then
  (
    cd "$module_dir"
    go mod edit "-replace=github.com/assurrussa/api=$repo_root"
  )
fi
cat > "$module_dir/consumer_test.go" <<'EOF'
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
	for _, tc := range []struct {
		name string
		options []api.Option
	}{
		{name: "strict"},
		{name: "arc", options: []api.Option{api.WithCache(arc.Factory(100), time.Minute)}},
		{name: "rcu", options: []api.Option{api.WithCache(rcu.Factory(5*time.Second), time.Minute)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, err := api.New(store, cfg, tc.options...)
			if err != nil { t.Fatal(err) }
			if err := service.Close(); err != nil { t.Fatal(err) }
		})
	}
}
EOF
(
  cd "$module_dir"
  go version
  go mod tidy
  if [ -n "$api_probe_version" ]; then
    api_resolved_version=$(go list -m -f '{{.Version}}' github.com/assurrussa/api)
    if [ "$api_resolved_version" != "$api_probe_version" ]; then
      printf 'Expected %s, resolved %s\n' "$api_probe_version" "$api_resolved_version" >&2
      exit 1
    fi
    api_replaced_modules=$(go list -m -f '{{if .Replace}}{{.Path}}{{end}}' all)
    if [ -n "$api_replaced_modules" ]; then
      printf 'Unexpected module replacements:\n%s\n' "$api_replaced_modules" >&2
      exit 1
    fi
    go mod verify
    go list -m -f '{{.Path}} {{.Version}} {{.Sum}} {{.GoModSum}}' github.com/assurrussa/api
  fi
  go test -v ./...
  go build ./...
)
if [ -n "$api_probe_version" ]; then
  printf 'Published consumer probe passed: github.com/assurrussa/api@%s (no replacements, fresh module cache).\n' "$api_probe_version"
else
  printf '%s\n' 'Local consumer probe passed (temporary module with local replace; not published-version evidence).'
fi
