#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off

api_e2e_container=''
api_e2e_test_pid=''
cleanup() {
  if [ -n "$api_e2e_test_pid" ]; then
    # The background test runner has its own process group, including CLI
    # servers. Also reap leftovers if go test times out or is interrupted.
    kill -TERM -- "-$api_e2e_test_pid" 2>/dev/null || true
  fi
  if [ -n "$api_e2e_container" ]; then
    docker rm --force --volumes "$api_e2e_container" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export API_E2E_RUN_ID="api-e2e-$$-$RANDOM"
# Docker can reassign an automatically allocated host port after stop/start.
# Choose and explicitly bind a temporary port; retry collisions without
# touching the process that already owns that port.
api_e2e_started=0
for ((attempt=0; attempt<5; attempt++)); do
  api_e2e_port=$((40000 + RANDOM % 20000))
  api_e2e_container=$(docker create \
    --label "api.e2e=$API_E2E_RUN_ID" --publish "127.0.0.1:$api_e2e_port:5432" \
    --env POSTGRES_USER=api_e2e --env POSTGRES_PASSWORD=local-e2e-only \
    --env POSTGRES_DB=api_e2e postgres:18.6-alpine)
  if docker start "$api_e2e_container" >/dev/null; then api_e2e_started=1; break; fi
  docker rm --force --volumes "$api_e2e_container" >/dev/null
  api_e2e_container=''
done
if [ "$api_e2e_started" != 1 ]; then echo 'Cannot bind E2E PostgreSQL port' >&2; exit 1; fi
export API_E2E_CONTAINER="$api_e2e_container"
api_e2e_binding=$(docker port "$api_e2e_container" 5432/tcp)
export API_E2E_DATABASE_URL="postgres://api_e2e:local-e2e-only@127.0.0.1:${api_e2e_binding##*:}/api_e2e?sslmode=disable&connect_timeout=1"
api_e2e_ready=0
for ((attempt=0; attempt<80; attempt++)); do
  if docker exec "$api_e2e_container" pg_isready -h 127.0.0.1 -U api_e2e -d api_e2e >/dev/null 2>&1; then
    api_e2e_ready=1
    break
  fi
  sleep 0.25
done
if [ "$api_e2e_ready" != 1 ]; then echo 'E2E PostgreSQL did not become ready' >&2; exit 1; fi

set -m
go test -tags=e2e -race -count=1 -timeout=4m -v ./e2e "$@" &
api_e2e_test_pid=$!
wait "$api_e2e_test_pid"
