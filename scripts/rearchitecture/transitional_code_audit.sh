#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

strict=1

usage() {
  cat <<'EOF'
usage: bash scripts/rearchitecture/transitional_code_audit.sh [--strict|--no-strict]

Checks for transitional naming markers and transitional comments in repository code/test assets.

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

printf '== Transitional Code Audit ==\n'
printf 'repo: %s\n\n' "$ROOT_DIR"

name_matches="$(find cmd internal pkg test -type f 2>/dev/null | rg 'legacy|compat|migration|transitional|temporary' || true)"
comment_matches="$(rg -n 'TODO|FIXME|temporary|compat' cmd internal pkg test || true)"

name_count="$(printf '%s\n' "$name_matches" | sed '/^$/d' | wc -l | tr -d ' ')"
comment_count="$(printf '%s\n' "$comment_matches" | sed '/^$/d' | wc -l | tr -d ' ')"

printf '[naming-matches]\n'
printf 'count: %s\n' "$name_count"
if [[ "$name_count" != "0" ]]; then
  printf '%s\n' "$name_matches"
fi
printf '\n'

printf '[comment-matches]\n'
printf 'count: %s\n' "$comment_count"
if [[ "$comment_count" != "0" ]]; then
  printf '%s\n' "$comment_matches"
fi
printf '\n'

printf '[triage]\n'
if [[ "$name_count" == "0" && "$comment_count" == "0" ]]; then
  printf 'no transitional markers found\n'
else
  printf 'review required\n'
fi

if [[ "$strict" == "1" && ( "$name_count" != "0" || "$comment_count" != "0" ) ]]; then
  printf '\nblocking: transitional code audit failed\n' >&2
  exit 1
fi
