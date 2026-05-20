#!/bin/bash
# CLI call-graph documentation guard
# Ensures CLI call-graph docs stay aligned with command registration and source anchors.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC_CN="$ROOT_DIR/docs/03-quick-start/03-01_cli.md"
DOC_EN="$ROOT_DIR/docs/03-quick-start/03-01_cli_en.md"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

ok() { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; WARNINGS=$((WARNINGS + 1)); }
err() { echo -e "${RED}❌ $1${NC}"; ERRORS=$((ERRORS + 1)); }

has_rg() {
  command -v rg >/dev/null 2>&1
}

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    err "Missing file: $path"
    return 1
  fi
  return 0
}

require_contains() {
  local file="$1"
  local needle="$2"
  local label="$3"
  if has_rg; then
    if rg -n -F "$needle" "$file" >/dev/null 2>&1; then
      ok "$label"
      return
    fi
  else
    if grep -n -F "$needle" "$file" >/dev/null 2>&1; then
      ok "$label"
      return
    fi
  fi
  err "$label (not found: $needle)"
}

extract_anchors() {
  local file="$1"
  if has_rg; then
    rg -o '`(cmd|internal)/[^`]+:[0-9]+`' "$file" | tr -d '`' | sort -u
  else
    grep -oE '`(cmd|internal)/[^`]+:[0-9]+`' "$file" | tr -d '`' | sort -u
  fi
}

check_tools() {
  if has_rg; then
    ok "ripgrep available (using rg)"
  else
    warn "ripgrep not found; falling back to grep"
  fi
}

check_docs_structure() {
  echo "Checking CLI docs structure..."
  require_file "$DOC_CN" || return
  require_file "$DOC_EN" || return

  require_contains "$DOC_CN" "## 调用链图" "CN section: 调用链图"
  require_contains "$DOC_CN" "## 维护规则" "CN section: 维护规则"
  require_contains "$DOC_CN" "## 抽样链路核对（2026-04-11）" "CN section: 抽样链路核对"

  require_contains "$DOC_EN" "## Call Graphs" "EN section: Call Graphs"
  require_contains "$DOC_EN" "## Maintenance Rules" "EN section: Maintenance Rules"
  require_contains "$DOC_EN" "## Sampled Call-Path Verification (2026-04-11)" "EN section: Sampled Call-Path Verification"

  require_contains "$DOC_CN" "dynamic|dyn" "CN alias marker: dynamic|dyn"
  require_contains "$DOC_CN" "del|delete" "CN alias marker: del|delete"
  require_contains "$DOC_CN" "on|load" "CN alias marker: on|load"
  require_contains "$DOC_CN" "off|unload" "CN alias marker: off|unload"

  require_contains "$DOC_EN" "dynamic|dyn" "EN alias marker: dynamic|dyn"
  require_contains "$DOC_EN" "del|delete" "EN alias marker: del|delete"
  require_contains "$DOC_EN" "on|load" "EN alias marker: on|load"
  require_contains "$DOC_EN" "off|unload" "EN alias marker: off|unload"
}

check_command_registration_baseline() {
  local root_go="$ROOT_DIR/cmd/netxfw/root.go"
  require_file "$root_go" || return

  echo "Checking root command registration baseline..."
  require_contains "$root_go" "RootCmd.AddCommand(agent.RuleCmd)" "root registers RuleCmd"
  require_contains "$root_go" "RootCmd.AddCommand(agent.SystemCmd)" "root registers SystemCmd"
  require_contains "$root_go" "RootCmd.AddCommand(agent.SimpleDenyCmd)" "root registers SimpleDenyCmd"
  require_contains "$root_go" "RootCmd.AddCommand(agent.DynamicCmd)" "root registers DynamicCmd"
  require_contains "$root_go" "RootCmd.AddCommand(agent.PerfCmd)" "root registers PerfCmd"
}

check_sampled_chain_symbols() {
  echo "Checking sampled-chain command symbols..."
  require_contains "$ROOT_DIR/cmd/agent/rule.go" "var ruleExportCmd = &cobra.Command{" "symbol: ruleExportCmd"
  require_contains "$ROOT_DIR/cmd/agent/system_xdp_commands.go" "var syncToMapCmd = &cobra.Command{" "symbol: syncToMapCmd"
  require_contains "$ROOT_DIR/cmd/agent/simple_list.go" "var denyPortListCmd = &cobra.Command{" "symbol: denyPortListCmd"
  require_contains "$ROOT_DIR/cmd/agent/dynamic.go" "var dynamicAddCmd = &cobra.Command{" "symbol: dynamicAddCmd"
  require_contains "$ROOT_DIR/cmd/agent/perf.go" "var perfShowCmd = &cobra.Command{" "symbol: perfShowCmd"
}

check_anchor_lines() {
  local doc="$1"
  local label="$2"
  echo "Checking source anchors in $label..."

  local anchors
  anchors="$(extract_anchors "$doc")"
  if [ -z "$anchors" ]; then
    warn "$label: no line-based anchors found"
    return
  fi

  while IFS= read -r anchor; do
    [ -z "$anchor" ] && continue
    local rel_path="${anchor%:*}"
    local line="${anchor##*:}"
    local abs_path="$ROOT_DIR/$rel_path"

    if [ ! -f "$abs_path" ]; then
      err "$label anchor target missing: $rel_path"
      continue
    fi

    if ! [[ "$line" =~ ^[0-9]+$ ]]; then
      err "$label invalid line number: $anchor"
      continue
    fi

    local max_line
    max_line="$(wc -l < "$abs_path" | tr -d ' ')"
    if [ "$line" -lt 1 ] || [ "$line" -gt "$max_line" ]; then
      err "$label out-of-range anchor: $anchor (max line: $max_line)"
      continue
    fi
  done <<< "$anchors"

  if [ "$ERRORS" -eq 0 ]; then
    ok "$label source anchors are valid"
  fi
}

main() {
  echo "======================================"
  echo "CLI Call Graph Documentation Check"
  echo "======================================"
  echo ""

  check_tools
  echo ""
  check_docs_structure
  echo ""
  check_command_registration_baseline
  echo ""
  check_sampled_chain_symbols
  echo ""
  check_anchor_lines "$DOC_CN" "CN doc"
  check_anchor_lines "$DOC_EN" "EN doc"
  echo ""

  echo "Summary: errors=$ERRORS warnings=$WARNINGS"
  if [ "$ERRORS" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
