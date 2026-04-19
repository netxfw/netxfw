#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

strict=1

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  fi
}

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

require_tool python3

paths=(
  "internal/application"
  "internal/core"
  "internal/xdp"
  "internal/plugins/types"
)

count_lines() {
  python3 -c 'import sys; print(sum(1 for line in sys.stdin if line.strip()))'
}

search_go_files() {
  local pattern="$1"
  python3 - "$ROOT_DIR" "$pattern" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(sys.argv[2])
search_roots = ["cmd", "internal", "pkg", "test"]

for relative_root in search_roots:
    base = root / relative_root
    if not base.exists():
        continue
    for path in sorted(base.rglob("*.go")):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                print(f"{path.relative_to(root)}:{lineno}:{line}")
PY
}

printf '== Import Audit ==\n'
printf 'repo: %s\n\n' "$ROOT_DIR"

total_matches=0

for path in "${paths[@]}"; do
  escaped_path="${path//\//\/}"
  matches="$(search_go_files "\"github\.com/netxfw/netxfw/${escaped_path}\"" || true)"
  count="$(printf '%s\n' "$matches" | count_lines)"
  printf '[%s]\n' "$path"
  printf 'count: %s\n' "$count"
  if [[ "$count" != "0" ]]; then
    printf '%s\n' "$matches"
  fi
  printf '\n'
  total_matches=$((total_matches + count))
done

compat_matches="$(python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/adapters internal/api internal/daemon internal/datapath internal/domain internal/metrics internal/optimizer internal/plugins internal/runtime internal/utils cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'legacy|compat|migration|transitional' || true)"
compat_count="$(printf '%s\n' "$compat_matches" | count_lines)"
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
