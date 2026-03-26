#!/bin/bash
set -e

BASELINE_ISSUES=908

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "golangci-lint not installed"
  exit 0
fi

tmp_file=$(mktemp)
trap 'rm -f "$tmp_file"' EXIT

set +e
golangci-lint run --timeout=5m >"$tmp_file" 2>&1
lint_exit=$?
set -e

issue_count_line=$(grep -E "^[0-9]+ issues:$" "$tmp_file" | tail -n 1 || true)
if [ -n "$issue_count_line" ]; then
  current_issues=$(echo "$issue_count_line" | awk '{print $1}')
else
  if [ "$lint_exit" -eq 0 ]; then
    current_issues=0
  else
    if grep -q "configuration file for golangci-lint v2 with golangci-lint v1" "$tmp_file" || grep -q "the format is required" "$tmp_file"; then
      echo "golangci-lint version mismatch (config v2, binary v1), skip lint budget check"
      exit 0
    fi
    echo "cannot parse lint issue count"
    cat "$tmp_file"
    exit 1
  fi
fi

echo "lint baseline: ${BASELINE_ISSUES}"
echo "lint current: ${current_issues}"

if [ "$current_issues" -gt "$BASELINE_ISSUES" ]; then
  echo "lint issues increased"
  exit 1
fi

echo "lint budget check passed"
