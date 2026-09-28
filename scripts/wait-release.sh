#!/usr/bin/env bash
# Wait for public Go services before creating the consumer's fresh module cache.
set -euo pipefail

api_release_version=${1:-}
api_version_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
if [ "$#" -ne 1 ] || [[ ! "$api_release_version" =~ $api_version_pattern ]]; then
  printf '%s\n' 'Usage: wait-release.sh vX.Y.Z[-prerelease]' >&2
  exit 2
fi
api_release_timeout=${API_RELEASE_WAIT_TIMEOUT:-2100}
if [[ ! "$api_release_timeout" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$api_release_timeout" -gt 86400 ]; then
  printf '%s\n' 'API_RELEASE_WAIT_TIMEOUT must be 1..86400 seconds (default: 2100).' >&2
  exit 2
fi

# Canonical pseudo-versions refer to commits and do not have corresponding tags.
api_pseudo_pattern='^v[0-9]+\.[0-9]+\.[0-9]+-([0-9A-Za-z.-]+\.)?[0-9]{14}-[0-9a-f]{12}$'
if [[ ! "$api_release_version" =~ $api_pseudo_pattern ]]; then
  if api_release_refs=$(GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code \
    https://github.com/assurrussa/api.git \
    "refs/tags/$api_release_version" "refs/tags/$api_release_version^{}"); then
    api_release_commit=$(printf '%s\n' "$api_release_refs" | awk '
      /\^\{\}$/ { peeled = $1 }
      !/\^\{\}$/ { tag = $1 }
      END { print (peeled != "" ? peeled : tag) }')
    printf 'Published tag %s: %s\n' "$api_release_version" "$api_release_commit"
  else
    api_release_git_status=$?
    if [ "$api_release_git_status" -eq 2 ]; then
      printf 'Tag %s is not published in github.com/assurrussa/api. Push the tag before running consumer-release.\n' "$api_release_version" >&2
    else
      printf 'Cannot check published tag %s in GitHub (git exit %s).\n' "$api_release_version" "$api_release_git_status" >&2
    fi
    exit 1
  fi
fi

api_release_dir=$(mktemp -d "${TMPDIR:-/tmp}/api-release-wait.XXXXXX")
api_release_sleep_pid=''
cleanup() {
  if [ -n "$api_release_sleep_pid" ]; then
    kill "$api_release_sleep_pid" 2>/dev/null || true
    wait "$api_release_sleep_pid" 2>/dev/null || true
  fi
  rm -rf "$api_release_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# curl may return several header blocks (CONNECT or redirects). Use the last one.
header_value() {
  awk -v name="$1" '
    /^HTTP\// { value = "" }
    index(tolower($0), name ":") == 1 {
      value = substr($0, length(name) + 2)
      sub(/^[ \t]+/, "", value)
      sub(/[ \t\r]+$/, "", value)
    }
    END { print value }' "$api_release_dir/headers"
}

http_date_epoch() {
  # GNU date, then BSD date (macOS).
  LC_ALL=C date -u -d "$1" +%s 2>/dev/null ||
    LC_ALL=C date -j -u -f '%a, %d %b %Y %H:%M:%S GMT' "$1" +%s 2>/dev/null
}

retry_delay() {
  local api_cache_control api_age api_delay api_expires api_retry api_epoch
  api_cache_control=$(header_value cache-control) || return
  api_age=$(header_value age) || return
  api_delay=$(awk -v control="$api_cache_control" -v age="$api_age" 'BEGIN {
    delay = -1
    count = split(tolower(control), directives, ",")
    for (i = 1; i <= count; i++) {
      gsub(/[ \t\"]/, "", directives[i])
      if (directives[i] ~ /^max-age=[0-9]+$/) {
        split(directives[i], pair, "=")
        delay = pair[2] - (age ~ /^[0-9]+$/ ? age : 0)
        if (delay < 0) delay = 0
      }
    }
    if (delay > 86400) delay = 86400
    printf "%.0f\n", delay
  }') || return
  if [ "$api_delay" -lt 0 ]; then
    api_delay=0
    api_expires=$(header_value expires) || return
    if [ -n "$api_expires" ] && api_epoch=$(http_date_epoch "$api_expires"); then
      api_delay=$((api_epoch - $1))
    fi
  fi
  api_retry=$(header_value retry-after) || return
  if [[ "$api_retry" =~ ^[0-9]+$ ]]; then
    api_epoch=$(awk -v seconds="$api_retry" 'BEGIN { printf "%.0f\n", (seconds > 86400 ? 86400 : seconds) }') || return
  elif [ -n "$api_retry" ] && api_epoch=$(http_date_epoch "$api_retry"); then
    api_epoch=$((api_epoch - $1))
  else
    api_epoch=0
  fi
  if [ "$api_epoch" -gt "$api_delay" ]; then api_delay=$api_epoch; fi
  if [ "$api_delay" -lt 0 ]; then api_delay=0; fi
  printf '%s\n' "$api_delay"
}

# The module protocol escapes uppercase version letters as !lowercase.
api_release_escaped=$(printf '%s' "$api_release_version" | awk '{
  for (i = 1; i <= length($0); i++) {
    letter = substr($0, i, 1)
    printf "%s", (letter ~ /[A-Z]/ ? "!" tolower(letter) : letter)
  }
}')
api_release_urls=(
  "https://proxy.golang.org/github.com/assurrussa/api/@v/$api_release_escaped.info"
  "https://proxy.golang.org/github.com/assurrussa/api/@v/$api_release_escaped.mod"
  "https://proxy.golang.org/github.com/assurrussa/api/@v/$api_release_escaped.zip"
  "https://sum.golang.org/lookup/github.com/assurrussa/api@$api_release_escaped"
)
api_release_started=$(date +%s)
api_release_deadline=$((api_release_started + api_release_timeout))
api_release_pending='public Go services'
while true; do
  api_release_delay=15
  api_release_previous=$api_release_pending
  api_release_pending=''
  for api_release_url in "${api_release_urls[@]}"; do
    api_release_remaining=$((api_release_deadline - $(date +%s)))
    if [ "$api_release_remaining" -le 0 ]; then
      printf 'Timed out after %ss waiting for %s: %s\n' "$api_release_timeout" "$api_release_version" "${api_release_pending:-$api_release_previous}" >&2
      exit 1
    fi
    api_release_request_timeout=$api_release_remaining
    if [ "$api_release_request_timeout" -gt 30 ]; then api_release_request_timeout=30; fi
    # HEAD checks availability without downloading the module or toolchain.
    if api_release_status=$(curl --disable --silent --show-error --head --location \
      --proto '=https' --proto-redir '=https' --connect-timeout 10 \
      --max-time "$api_release_request_timeout" --dump-header "$api_release_dir/headers" \
      --output /dev/null --write-out '%{http_code}' "$api_release_url"); then
      case "$api_release_status" in
        200) continue ;;
        404|429|5??) ;;
        *) printf 'Cannot check %s: HTTP %s.\n' "$api_release_url" "$api_release_status" >&2; exit 1 ;;
      esac
      api_release_hint=$(retry_delay "$(date +%s)")
      if [ "$api_release_hint" -ge "$api_release_delay" ]; then api_release_delay=$((api_release_hint + 1)); fi
    else
      api_release_curl_status=$?
      case "$api_release_curl_status" in
        6|7|28|52|56) api_release_status="network error $api_release_curl_status" ;;
        *) printf 'Cannot check %s (curl exit %s).\n' "$api_release_url" "$api_release_curl_status" >&2; exit 1 ;;
      esac
    fi
    api_release_pending="${api_release_pending:+$api_release_pending; }$api_release_url: $api_release_status"
  done
  if [ -z "$api_release_pending" ]; then
    printf '%s is available through Go proxy and checksum database. Starting the clean consumer probe.\n' "$api_release_version"
    break
  fi
  api_release_remaining=$((api_release_deadline - $(date +%s)))
  if [ "$api_release_remaining" -lt "$api_release_delay" ]; then api_release_delay=$api_release_remaining; fi
  if [ "$api_release_delay" -gt 0 ]; then
    printf 'Waiting for %s. Retry in %ss (timeout in %ss).\n' "$api_release_pending" "$api_release_delay" "$api_release_remaining"
    sleep "$api_release_delay" &
    api_release_sleep_pid=$!
    wait "$api_release_sleep_pid"
    api_release_sleep_pid=''
  fi
done
