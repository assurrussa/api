#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off

bash scripts/test-consumer-release.sh
bash scripts/lint.sh run --timeout=5m ./...

api_test_container=''
cleanup() {
  if [ -n "$api_test_container" ]; then docker stop "$api_test_container" >/dev/null; fi
}
trap cleanup EXIT

if [ -z "${API_TEST_DATABASE_URL:-}" ]; then
  api_test_container=$(docker run --detach --rm --publish 127.0.0.1::5432 \
    --env POSTGRES_USER=api_test --env POSTGRES_PASSWORD=local-test-only \
    --env POSTGRES_DB=api_test postgres:18.6-alpine)
  api_test_binding=$(docker port "$api_test_container" 5432/tcp)
  export API_TEST_DATABASE_URL="postgres://api_test:local-test-only@127.0.0.1:${api_test_binding##*:}/api_test?sslmode=disable"
  api_test_ready=0
  for ((attempt=0; attempt<40; attempt++)); do
    if docker exec "$api_test_container" pg_isready -h 127.0.0.1 -U api_test -d api_test >/dev/null 2>&1; then api_test_ready=1; break; fi
    sleep 0.25
  done
  if [ "$api_test_ready" != 1 ]; then echo 'Test PostgreSQL did not become ready' >&2; exit 1; fi
fi

api_unformatted=$(gofmt -l .)
if [ -n "$api_unformatted" ]; then printf 'Unformatted Go files:\n%s\n' "$api_unformatted" >&2; exit 1; fi
go vet ./...
go test -race -count=1 ./...
bash scripts/consumer-probe.sh
bash scripts/e2e.sh
