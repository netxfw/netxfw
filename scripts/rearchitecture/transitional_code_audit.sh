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

require_tool python3

count_lines() {
  python3 -c 'import sys; print(sum(1 for line in sys.stdin if line.strip()))'
}

search_files() {
  local pattern="$1"
  local excludes_regex="${2:-}"
  python3 - "$ROOT_DIR" "$pattern" "$excludes_regex" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(sys.argv[2])
exclude_pattern = re.compile(sys.argv[3]) if sys.argv[3] else None
search_roots = ["cmd", "internal", "pkg", "test"]

for relative_root in search_roots:
    base = root / relative_root
    if not base.exists():
        continue
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        relative_str = str(relative)
        if exclude_pattern and exclude_pattern.search(relative_str):
            continue
        if pattern.search(relative_str):
            print(relative_str)
PY
}

search_content() {
  local pattern="$1"
  python3 - "$ROOT_DIR" "$pattern" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(sys.argv[2])
search_roots = ["cmd", "internal", "pkg", "test"]
skip_suffixes = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".bin", ".o", ".so", ".a"}

for relative_root in search_roots:
    base = root / relative_root
    if not base.exists():
        continue
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() in skip_suffixes:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                print(f"{path.relative_to(root)}:{lineno}:{line}")
PY
}

printf '== Transitional Code Audit ==\n'
printf 'repo: %s\n\n' "$ROOT_DIR"

name_matches="$(search_files 'legacy|compat|migration|transitional|temporary' '(^|/)(test|tests)/|_test\.go$|internal/config/|internal/configtypes/|internal/domain/config/sdk_compat\.go$|internal/ports/sdk_compat\.go$' || true)"
comment_matches="$(python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/adapters internal/api internal/daemon internal/datapath internal/domain internal/metrics internal/optimizer internal/plugins internal/runtime internal/utils cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'TODO|FIXME|temporary|compat' || true)"

name_count="$(printf '%s\n' "$name_matches" | count_lines)"
comment_count="$(printf '%s\n' "$comment_matches" | count_lines)"

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
