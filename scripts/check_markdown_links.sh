#!/bin/bash
# Markdown link check entrypoint for repo-level docs.
# 仓库级 Markdown 链接检查入口。

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS_CHECKER="$ROOT_DIR/docs/check_links.sh"

if [ ! -x "$DOCS_CHECKER" ]; then
  chmod +x "$DOCS_CHECKER" 2>/dev/null || true
fi

check_file_links() {
  local file="$1"
  local dir
  dir="$(dirname "$file")"
  local failed=0

  while IFS= read -r link; do
    [[ -z "$link" ]] && continue
    [[ "$link" =~ ^https?:// ]] && continue
    [[ "$link" =~ ^# ]] && continue
    [[ "$link" =~ ^mailto: ]] && continue

    local clean_link="$link"
    clean_link="${clean_link%%#*}"
    clean_link="${clean_link%%\?*}"
    [[ -z "$clean_link" ]] && continue

    local target
    target="$(realpath -m "$dir/$clean_link")"
    if [ ! -e "$target" ]; then
      echo "❌ Broken link in $file -> $link"
      failed=1
    fi
  done < <(grep -oE '\]\(([^)]+)\)' "$file" | sed -E 's/^\]\((.*)\)$/\1/')

  return $failed
}

main() {
  local failed=0
  local files=(
    "$ROOT_DIR/README.md"
    "$ROOT_DIR/README_en.md"
  )

  if [ -f "$ROOT_DIR/ARCHITECTURE.md" ]; then
    files+=("$ROOT_DIR/ARCHITECTURE.md")
  fi

  echo "=== Checking repository markdown links ==="
  "$DOCS_CHECKER" -d "$ROOT_DIR/docs"

  for file in "${files[@]}"; do
    echo "Checking $file"
    if ! check_file_links "$file"; then
      failed=1
    fi
  done

  if [ "$failed" -ne 0 ]; then
    exit 1
  fi

  echo "✅ Repository markdown link checks passed"
}

main "$@"
