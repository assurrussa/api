#!/usr/bin/env bash
# Exercise the real release entry point without network access or wall-clock waits.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api_test_root=$(mktemp -d "${TMPDIR:-/tmp}/api-consumer-release-test.XXXXXX")
trap 'rm -rf "$api_test_root"' EXIT
export API_TEST_REAL_DATE
API_TEST_REAL_DATE=$(command -v date)
mkdir "$api_test_root/bin"
ln -s "$BASH" "$api_test_root/bin/bash"

cat > "$api_test_root/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'git %s\n' "$*" >> "$API_TEST_STATE/calls"
case "$API_TEST_SCENARIO" in
  missing_tag) exit 2 ;;
  git_failure) exit 128 ;;
esac
printf '1111111111111111111111111111111111111111\trefs/tags/%s\n' "$API_TEST_VERSION"
printf '2222222222222222222222222222222222222222\trefs/tags/%s^{}\n' "$API_TEST_VERSION"
EOF

cat > "$api_test_root/bin/date" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = '+%s' ]; then
  cat "$API_TEST_STATE/clock"
else
  exec "$API_TEST_REAL_DATE" "$@"
fi
EOF

cat > "$api_test_root/bin/sleep" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'sleep %s\n' "$1" >> "$API_TEST_STATE/calls"
printf '%s\n' "$(( $(cat "$API_TEST_STATE/clock") + $1 ))" > "$API_TEST_STATE/clock"
EOF

cat > "$api_test_root/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
headers=''
request_timeout=''
head_request=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dump-header) headers=$2; shift ;;
    --max-time) request_timeout=$2; shift ;;
    --head) head_request=true ;;
    https://*) url=$1 ;;
  esac
  shift
done
[ "$head_request" = true ]
printf 'curl %s\n' "$url" >> "$API_TEST_STATE/calls"
status=200
extra=''
if [ "$(cat "$API_TEST_STATE/clock")" -eq 1000 ] || [ "$API_TEST_SCENARIO" = timeout ]; then
  case "$API_TEST_SCENARIO:$url" in
    cached_404:*.info)
      status=404
      extra=$'Cache-Control: public, max-age=1800\r\nAge: 1680\r\n'
      ;;
    zip_pending:*.zip|sumdb_pending:*sum.golang.org*) status=404 ;;
    timeout:*.info) status=404; extra=$'Cache-Control: max-age=1800\r\n' ;;
    forbidden:*.info) status=403 ;;
    gone:*.info) status=410 ;;
    throttled:*.info) status=429; extra=$'Retry-After: 30\r\n' ;;
    unavailable:*.info) status=503; extra=$'Retry-After: Thu, 01 Jan 1970 00:17:10 GMT\r\n' ;;
    expires:*.info) status=404; extra=$'Expires: Thu, 01 Jan 1970 00:17:10 GMT\r\n' ;;
    expired:*.info) status=404; extra=$'Cache-Control: max-age=30\r\nAge: 60\r\n' ;;
    network:*.info) exit 28 ;;
    tls_error:*.info) exit 60 ;;
    request_budget:*.info)
      [ "$request_timeout" -eq 7 ]
      printf '1007\n' > "$API_TEST_STATE/clock"
      exit 28
      ;;
  esac
fi
# Ignore a redirect's headers when interpreting the final response's TTL.
printf 'HTTP/1.1 302 Found\r\nCache-Control: max-age=86400\r\n\r\nHTTP/2 %s\r\n%s\r\n' "$status" "$extra" > "$headers"
printf '%s' "$status"
EOF

cat > "$api_test_root/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'go %s\n' "$*" >> "$API_TEST_STATE/calls"
[ "$GOWORK" = off ] && [ "$GOENV" = off ] && [ "$GOTOOLCHAIN" = go1.27.1 ]
[ "$GOPROXY" = https://proxy.golang.org ] && [ "$GOSUMDB" = sum.golang.org ]
[ -z "$GOFLAGS$GOPRIVATE$GONOPROXY$GONOSUMDB" ]
[ ! -e "$GOMODCACHE" ] || [ -d "$GOMODCACHE" ]
if [ -f "$API_TEST_STATE/module-cache" ]; then
  [ "$GOMODCACHE" = "$(cat "$API_TEST_STATE/module-cache")" ]
else
  printf '%s\n' "$GOMODCACHE" > "$API_TEST_STATE/module-cache"
  mkdir "$GOMODCACHE"
fi
case "$*" in
  'list -m -f {{.Version}} '*) printf '%s\n' "$API_TEST_VERSION" ;;
  'list -m -f {{.GoMod}} '*) printf '%s/published.mod\n' "$API_TEST_STATE" ;;
  'mod verify')
    if [ "$API_TEST_SCENARIO" = checksum_error ]; then
      printf '%s\n' 'SECURITY ERROR: checksum mismatch' >&2
      exit 1
    fi
    ;;
  'test -v ./...')
    if [ "$API_TEST_SCENARIO" = test_failure ]; then exit 1; fi
    ;;
esac
EOF
chmod +x "$api_test_root/bin/"*
export PATH="$api_test_root/bin:$PATH"
export API_TEST_STATE API_TEST_SCENARIO API_TEST_VERSION TMPDIR

fail() {
  printf 'FAIL: %s: %s\n' "$API_TEST_SCENARIO" "$1" >&2
  cat "$API_TEST_STATE/output" "$API_TEST_STATE/calls" >&2
  exit 1
}

run_case() {
  API_TEST_SCENARIO=$1
  API_TEST_VERSION=${3:-v0.1.0}
  API_TEST_STATE="$api_test_root/$API_TEST_SCENARIO-$API_TEST_VERSION"
  mkdir "$API_TEST_STATE" "$API_TEST_STATE/tmp"
  TMPDIR="$API_TEST_STATE/tmp"
  printf '1000\n' > "$API_TEST_STATE/clock"
  : > "$API_TEST_STATE/calls"
  local api_test_status=0
  API_RELEASE_WAIT_TIMEOUT=${4:-2100} bash "$repo_root/scripts/consumer-probe.sh" --version "$API_TEST_VERSION" > "$API_TEST_STATE/output" 2>&1 || api_test_status=$?
  if [ "$api_test_status" -ne "$2" ]; then fail "expected exit $2, got $api_test_status"; fi
  # Both the wait and the consumer must remove their own temporary directories.
  if [ -n "$(ls -A "$TMPDIR")" ]; then fail 'temporary files were not removed'; fi
}

require_call() { if ! grep -F -- "$1" "$API_TEST_STATE/calls" >/dev/null; then fail "missing call: $1"; fi; }
reject_call() { if grep -F -- "$1" "$API_TEST_STATE/calls" >/dev/null; then fail "unexpected call: $1"; fi; }
require_output() { if ! grep -F -- "$1" "$API_TEST_STATE/output" >/dev/null; then fail "missing output: $1"; fi; }
require_clean_probe() {
  [ "$(grep -c '^go version$' "$API_TEST_STATE/calls")" -eq 1 ] || fail 'consumer was started more than once'
  require_call 'go mod verify'
  require_call 'go test -v ./...'
  require_call 'go build ./...'
  require_output 'Published consumer probe passed:'
  # All readiness requests must precede the first Go invocation.
  awk '/^go / { started = 1 } /^curl / && started { exit 1 }' "$API_TEST_STATE/calls" || fail 'retried readiness after starting Go'
}

run_case missing_tag 1
require_output 'is not published'
reject_call 'curl '
reject_call 'go '
run_case git_failure 1
require_output 'git exit 128'
reject_call 'curl '
reject_call 'go '
run_case ready 0
require_clean_probe
reject_call 'sleep '
require_output 'Published tag v0.1.0: 2222222222222222222222222222222222222222'
run_case cached_404 0
require_call 'sleep 121'
require_clean_probe
for api_test_scenario in zip_pending sumdb_pending expired network; do
  run_case "$api_test_scenario" 0
  require_call 'sleep 15'
  require_clean_probe
done
for api_test_scenario in throttled unavailable expires; do
  run_case "$api_test_scenario" 0
  require_call 'sleep 31'
  require_clean_probe
done
run_case timeout 1 v0.1.0 30
require_call 'sleep 30'
require_output 'Timed out after 30s'
reject_call 'go '
run_case request_budget 1 v0.1.0 7
require_output 'Timed out after 7s'
reject_call 'go '
for api_test_scenario in forbidden gone tls_error; do
  run_case "$api_test_scenario" 1
  reject_call 'sleep '
  reject_call 'go '
done
for api_test_version in v0.0.0-20260928112820-64c9164b375a v0.1.1-0.20260928112820-64c9164b375a v0.1.0-rc.1.0.20260928112820-64c9164b375a; do
  run_case pseudo 0 "$api_test_version"
  reject_call 'git '
  require_clean_probe
done
run_case uppercase 0 v0.1.0-RC.1
require_call 'refs/tags/v0.1.0-RC.1'
require_call '/@v/v0.1.0-!r!c.1.info'
require_call 'sum.golang.org/lookup/github.com/assurrussa/api@v0.1.0-!r!c.1'
require_clean_probe
run_case checksum_error 1
require_output 'checksum mismatch'
reject_call 'sleep '
reject_call 'go test '
run_case test_failure 1
require_call 'go test -v ./...'
reject_call 'sleep '
reject_call 'go build '
run_case invalid_timeout 2 v0.1.0 0
reject_call 'git '
reject_call 'curl '
reject_call 'go '
run_case invalid_version 2 latest
reject_call 'git '
reject_call 'curl '
reject_call 'go '
printf '%s\n' 'Consumer release regression tests passed.'
