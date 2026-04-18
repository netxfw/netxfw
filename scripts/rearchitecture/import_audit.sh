#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

strict=1

usage() {
  cat <<'EOF'
usage: bash scripts/rearchitecture/import_audit.sh [--strict|--no-strict]

Checks for imports of removed legacy package paths and transitional markers in Go files.

Exit codes:
  0  no violations found, or violations found while running with --no-strict
  1  violations found while running in strict mode
  2  invalid arguments
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      strict=1
      shift
      ;;
    --no-strict)
      strict=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

paths=(
  "internal/application"
  "internal/core"
  "internal/xdp"
  "internal/plugins/types"
)

printf '== Import Audit ==\n'
printf 'repo: %s\n\n' "$ROOT_DIR"

total_matches=0

for path in "${paths[@]}"; do
  matches="$(rg -n "\"github.com/netxfw/netxfw/${path}\"" cmd internal pkg test --glob '*.go' || true)"
  count="$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')"
  printf '[%s]\n' "$path"
  printf 'count: %s\n' "$count"
  if [[ "$count" != "0" ]]; then
    printf '%s\n' "$matches"
  fi
  printf '\n'
  total_matches=$((total_matches + count))
done

compat_matches="$(rg -n 'legacy|compat|migration|transitional' cmd internal pkg test --glob '*.go' || true)"
compat_count="$(printf '%s\n' "$compat_matches" | sed '/^$/d' | wc -l | tr -d ' ')"
printf '[transitional-markers-in-go-files]\n'
printf 'count: %s\n' "$compat_count"
if [[ "$compat_count" != "0" ]]; then
  printf '%s\n' "$compat_matches"
fi
printf '\n'

printf 'total-old-path-import-matches: %s\n' "$total_matches"

if [[ "$strict" == "1" ]]; then
  if [[ "$total_matches" != "0" || "$compat_count" != "0" ]]; then
    printf '\nblocking: import audit failed\n' >&2
    exit 1
  fi
fi
