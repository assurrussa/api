#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off

api_lint_version=$(cat .golangci-lint-version)
api_lint_binary="$PWD/bin/golangci-lint"
if [ ! -x "$api_lint_binary" ]; then
  api_lint_binary=$(command -v golangci-lint || true)
fi
if [ -z "$api_lint_binary" ]; then
  printf 'golangci-lint %s is required; see README.md installation instructions.\n' "$api_lint_version" >&2
  exit 1
fi
api_lint_actual=$("$api_lint_binary" version | awk '{for (i=1; i<NF; i++) if ($i == "version") {print $(i+1); exit}}')
if [ "$api_lint_actual" != "$api_lint_version" ]; then
  printf 'golangci-lint %s is required; found %s at %s. See README.md.\n' "$api_lint_version" "$api_lint_actual" "$api_lint_binary" >&2
  exit 1
fi
exec "$api_lint_binary" "$@"
