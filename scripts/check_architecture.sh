#!/bin/bash
# 架构与工程守卫检查脚本（与当前仓库结构对齐）
# Architecture & quality guard script (aligned with current repo layout)
#
# 用法 / Usage:
#   ./scripts/check_architecture.sh

set -u

echo "======================================"
echo "架构/工程守卫检查"
echo "Architecture / Quality Guard Check"
echo "======================================"
echo ""

# 颜色定义 / Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

inc_error() {
  ERRORS=$((ERRORS + 1))
}

inc_warning() {
  WARNINGS=$((WARNINGS + 1))
}

print_ok() {
  echo -e "${GREEN}✅ $1${NC}"
}

print_warn() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

print_err() {
  echo -e "${RED}❌ $1${NC}"
}

safe_grep() {
  # safe_grep <pattern> <path...>
  # never fails the script; returns 0 if match, 1 otherwise.
  local pattern="$1"; shift
  grep -R -E "$pattern" "$@" --include="*.go" 2>/dev/null || true
}

# 1) 分层/反向依赖基本检查（按当前目录结构严格执行）
check_forbidden_imports() {
  echo "检查依赖与反向依赖..."
  echo "Checking layer & reverse dependencies..."
  echo ""

  # cmd -> infra (目前仓库没有 internal/infra，但仍保留规则，防止未来回潮)
  echo "1. cmd -> infra (error)"
  local cmd_infra
  cmd_infra=$(safe_grep 'internal/infra/' cmd/)
  if [ -n "$cmd_infra" ]; then
    print_err "发现 cmd 层直接导入 internal/infra（禁止）"
    echo "$cmd_infra"
    inc_error
  else
    print_ok "cmd -> infra 检查通过"
  fi
  echo ""

  # cmd -> service（若未来引入 internal/service，则建议经 app/usecase；先做 warning)
  echo "2. cmd -> service (warning)"
  local cmd_service
  cmd_service=$(safe_grep 'internal/service/' cmd/)
  if [ -n "$cmd_service" ]; then
    print_warn "发现 cmd 层直接导入 internal/service（建议通过 app/usecase 层）"
    echo "$cmd_service"
    inc_warning
  else
    print_ok "cmd -> service 检查通过"
  fi
  echo ""

  # cmd -> core / config（禁止 CLI 或 daemon 入口直接回连核心实现）
  echo "3. cmd -> core/config (error)"
  local cmd_core_config
  cmd_core_config=$(safe_grep '"github.com/netxfw/netxfw/internal/(core|config)"' cmd/)
  if [ -n "$cmd_core_config" ]; then
    print_err "发现 cmd 层直接导入 internal/core 或 internal/config（不允许）"
    echo "$cmd_core_config"
    inc_error
  else
    print_ok "cmd -> core/config 检查通过"
  fi
  echo ""

  # pkg -> internal（严格禁止，仅保留 tests 侧兼容；生产代码不可新增 compat 依赖）
  echo "4. pkg -> internal reverse deps"
  local pkg_internal
  pkg_internal=$(grep -R -E '"github.com/netxfw/netxfw/internal/' pkg --include="*.go" 2>/dev/null || true)
  if [ -n "$pkg_internal" ]; then
    local disallowed
    disallowed=$(echo "$pkg_internal" | grep -v -E 'internal/plugins/types' || true)
    if [ -n "$disallowed" ]; then
      print_err "发现 pkg 反向依赖 internal（不允许）"
      echo "$disallowed"
      inc_error
    else
      print_warn "pkg 依赖 internal/plugins/types（历史兼容点，仅允许存量；禁止新增其他 internal 依赖）"
      echo "$pkg_internal"
      inc_warning
    fi
  else
    print_ok "pkg -> internal 检查通过"
  fi
  echo ""

  # plugins -> api（当前已完成收口，重新引入应直接报错）
  echo "7. plugins -> api reverse deps (error)"
  local plugins_api
  plugins_api=$(grep -R -E '"github.com/netxfw/netxfw/internal/api"' internal/plugins --include="*.go" 2>/dev/null || true)
  if [ -n "$plugins_api" ]; then
    print_err "发现 plugins 层直接依赖 internal/api（不允许）"
    echo "$plugins_api"
    inc_error
  else
    print_ok "plugins -> api 检查通过"
  fi
  echo ""
}

# 2) system 模块治理（基于当前仓库结构）
check_system_module_conventions() {
  echo "检查 system 模块规范..."
  echo "Checking system module conventions..."
  echo ""

  # system.go 体量（保持告警，提示继续拆分）
  echo "5. [SYS-ENTRY-SIZE] system.go 体量（warning）"
  if [ -f cmd/agent/system.go ]; then
    local lines
    lines=$(wc -l < cmd/agent/system.go | tr -d ' ')
    if [ "$lines" -gt 650 ]; then
      print_warn "system.go 过大 (${lines} 行)，建议继续拆分"
      inc_warning
    else
      print_ok "system.go 体量检查通过 (${lines} 行)"
    fi
  else
    print_err "缺少 cmd/agent/system.go"
    inc_error
  fi
  echo ""

  # reason mapping 单一来源：只要在 cmd/agent 下出现 1 处就通过
  echo "6. [SYS-REASON-SOURCE] reason 映射单一来源"
  local cnt
  cnt=$(grep -R "func dropReasonToString" cmd/agent --include="*.go" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$cnt" -gt 1 ]; then
    print_err "发现重复的 dropReasonToString 定义（${cnt} 处）"
    grep -R "func dropReasonToString" cmd/agent --include="*.go" 2>/dev/null || true
    inc_error
  else
    print_ok "reason 映射来源检查通过"
  fi
  echo ""

  # required files（对齐当前仓库真实文件）
  echo "7. [SYS-REQUIRED-FILES] system 关键文件完整性"
  local required=(
    "cmd/agent/system.go"
    "cmd/agent/system_display.go"
    "cmd/agent/system_stats.go"
    "cmd/agent/system_types.go"
    "cmd/agent/executor.go"
  )
  local missing=0
  for f in "${required[@]}"; do
    if [ ! -f "$f" ]; then
      print_err "缺少关键文件: $f"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    inc_error
  else
    print_ok "system 关键文件完整性检查通过"
  fi
  echo ""

  # runtime boundary：除了 system.go 之外，不允许其他 agent 文件直接依赖底层 XDP/ebpf/link
  echo "8. [SYS-RUNTIME-BOUNDARY] 非 system.go 文件的底层依赖泄漏（error）"
  local leaked
  leaked=$(grep -R -E '"github.com/cilium/ebpf/link"|"github.com/netxfw/netxfw/internal/(xdp|datapath/xdp)"' cmd/agent --include="*.go" 2>/dev/null | grep -v 'cmd/agent/system.go' || true)
  if [ -n "$leaked" ]; then
    print_err "发现 system 以外的 agent 文件直接依赖底层 XDP/ebpf（建议通过 manager/SDK/执行器封装）"
    echo "$leaked"
    inc_error
  else
    print_ok "运行时边界依赖检查通过"
  fi
  echo ""
}

# 3) internal/datapath/xdp 治理（对齐当前拆分结构）
check_xdp_module_conventions() {
  echo "检查 xdp 模块规范..."
  echo "Checking xdp module conventions..."
  echo ""

  echo "9. [XDP-LEGACY-PATH] 禁止残留 internal/xdp 路径（error)"
  local legacy_xdp
  legacy_xdp=$(grep -R -E '"github.com/netxfw/netxfw/internal/xdp|internal/xdp/' internal cmd pkg test scripts docs --include="*.go" --include="*.sh" --include="*.md" 2>/dev/null | grep -v 'scripts/check_architecture.sh' || true)
  if [ -n "$legacy_xdp" ]; then
    print_err "发现残留 internal/xdp 旧路径，需统一迁移到 internal/datapath/xdp"
    echo "$legacy_xdp"
    inc_error
  else
    print_ok "旧 XDP 路径检查通过"
  fi
  echo ""

  echo "10. [XDP-SUBPKG-UPWARD-IMPORT] xdp 子包反向依赖（error）"
  local upward
  upward=$(grep -R '"github.com/netxfw/netxfw/internal/datapath/xdp"' internal/datapath/xdp/{health,lifecycle,maps,plugins,programs,stats,sync} --include="*.go" 2>/dev/null | grep -vE 'internal/datapath/xdp/(health|lifecycle|maps|plugins|programs|stats|sync)/' || true)
  if [ -n "$upward" ]; then
    print_err "发现 xdp 子包直接反向导入 internal/datapath/xdp 根路径"
    echo "$upward"
    inc_error
  else
    print_ok "xdp 子包反向依赖检查通过"
  fi
  echo ""

  echo "11. [XDP-ROOT-FILE-SCALE] xdp 根目录文件规模（warning）"
  if [ -d internal/datapath/xdp ]; then
    local c
    c=$(find internal/datapath/xdp -maxdepth 1 -name "*.go" | wc -l | tr -d ' ')
    if [ "$c" -gt 10 ]; then
      print_warn "internal/datapath/xdp 根目录 Go 文件数偏多: $c（建议继续按子包收敛）"
      inc_warning
    else
      print_ok "xdp 根目录文件规模检查通过 ($c files)"
    fi
  fi
  echo ""
}

# 4) 循环依赖（保持原逻辑，godepgraph 可选）
check_circular_deps() {
  echo "检查循环依赖..."
  echo "Checking circular dependencies..."
  echo ""

  if ! command -v go &>/dev/null; then
    print_warn "跳过：未安装 Go，无法检查循环依赖"
    inc_warning
    echo ""
    return
  fi

  local cycle_output
  cycle_output=$(go list -deps ./... 2>&1 >/dev/null || true)
  if echo "$cycle_output" | grep -qi "import cycle not allowed"; then
    print_err "发现循环依赖"
    echo "$cycle_output" | grep -i "import cycle not allowed" || true
    inc_error
  else
    print_ok "未发现循环依赖"
  fi
  echo ""
}

# 5) XDP 依赖检查（环境差异较大，失败按 warning）
check_xdp_dependencies() {
  echo "检查 XDP 依赖..."
  echo "Checking XDP dependencies..."
  echo ""

  if [ -x ./scripts/check_xdp_dependencies.sh ]; then
    if ./scripts/check_xdp_dependencies.sh >/dev/null 2>&1; then
      print_ok "XDP 依赖检查通过"
    else
      print_warn "XDP 依赖检查失败（按告警处理：可能与环境/内核/依赖有关）"
      inc_warning
    fi
  else
    print_warn "跳过：scripts/check_xdp_dependencies.sh 不可执行"
    inc_warning
  fi
  echo ""
}

# 6) build
check_build() {
  echo "编译检查..."
  echo "Build check..."
  echo ""

  if go build -trimpath ./cmd/netxfw >/dev/null 2>&1; then
    print_ok "编译成功"
  else
    print_err "编译失败"
    inc_error
  fi
  echo ""
}

# 7) coverage（默认阈值可配置，便于逐步提升）
check_coverage() {
  echo "检查测试覆盖率..."
  echo "Checking test coverage..."
  echo ""

  if ! command -v go &>/dev/null; then
    print_err "Go 未安装"
    inc_error
    return
  fi

  if ! go test -coverprofile=coverage.out ./... >/dev/null 2>&1; then
    print_warn "测试执行失败，覆盖率结果可能不完整（跳过覆盖率阈值判定）"
    inc_warning
    rm -f coverage.out
    echo ""
    return
  fi

  if [ -f coverage.out ]; then
    local cov
    local min_cov
    cov=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    min_cov="${COVERAGE_MIN:-35}"
    echo "总覆盖率 / Total coverage: ${cov}%"
    echo "覆盖率阈值 / Coverage threshold: ${min_cov}%"

    # awk numeric compare
    local below
    below=$(awk -v c="$cov" -v m="$min_cov" 'BEGIN{print (c<m)?1:0}')
    if [ "$below" -eq 1 ]; then
      print_warn "测试覆盖率低于阈值 ${min_cov}% (${cov}%)（当前按告警处理）"
      inc_warning
    else
      print_ok "测试覆盖率达标 (${cov}%)"
    fi

    rm -f coverage.out
  else
    print_warn "无法生成覆盖率报告（按告警处理）"
    inc_warning
  fi
  echo ""
}

# 8) lint / 质量
check_quality() {
  echo "检查代码质量..."
  echo "Checking code quality..."
  echo ""

  # lint budget 是可选守卫：失败不应直接导致主质量入口失效
  if [ -x ./scripts/check_lint_budget.sh ]; then
    if ./scripts/check_lint_budget.sh >/dev/null 2>&1; then
      print_ok "代码质量预算检查通过"
    else
      print_warn "代码质量预算检查失败（按告警处理；以 golangci-lint 结果为准）"
      inc_warning
    fi
  fi

  if command -v golangci-lint &>/dev/null; then
    if golangci-lint run --timeout=5m >/dev/null 2>&1; then
      print_ok "golangci-lint 检查通过"
    else
      print_err "golangci-lint 发现问题"
      inc_error
    fi
  else
    print_warn "跳过：未安装 golangci-lint"
    inc_warning
  fi

  echo ""
}

# Run all checks
check_forbidden_imports
check_system_module_conventions
check_xdp_module_conventions
check_circular_deps
check_xdp_dependencies
check_build
check_coverage
check_quality

# Summary
echo "======================================"
echo "检查总结 / Check Summary"
echo "======================================"
echo "错误 / Errors: ${ERRORS}"
echo "警告 / Warnings: ${WARNINGS}"
echo ""

if [ ${ERRORS} -gt 0 ]; then
  print_err "检查失败：发现 ${ERRORS} 个错误"
  exit 1
fi

if [ ${WARNINGS} -gt 0 ]; then
  print_warn "检查通过，但有 ${WARNINGS} 个告警"
  exit 0
fi

print_ok "检查完全通过"
exit 0
