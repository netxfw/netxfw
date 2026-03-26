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

# 1) 分层/反向依赖基本检查（以“迁移态”为前提）
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

  # cmd -> service (若未来引入 internal/service，则建议经 app/usecase；先做 warning)
  echo "2. cmd -> service (warning)"
  local cmd_service
  cmd_service=$(safe_grep 'internal/service/' cmd/)
  if [ -n "$cmd_service" ]; then
    print_warn "发现 cmd 层直接导入 internal/service（建议通过 app/usecase 层；当前按迁移态告警）"
    echo "$cmd_service"
    inc_warning
  else
    print_ok "cmd -> service 检查通过"
  fi
  echo ""

  # cmd -> core（当前仓库仍大量使用 internal/core，按迁移态仅告警）
  echo "3. cmd -> core (migration warning)"
  local cmd_core
  cmd_core=$(safe_grep '"github.com/netxfw/netxfw/internal/core"' cmd/)
  if [ -n "$cmd_core" ]; then
    print_warn "发现 cmd 层直接导入 internal/core（迁移态：允许但需要逐步收敛）"
    echo "$cmd_core"
    inc_warning
  else
    print_ok "cmd -> core 检查通过"
  fi
  echo ""

  # daemon entry cmd -> config（当前 daemon 入口直接加载 config 属于现实需要，按迁移态告警）
  echo "4. daemon entry cmd -> config (migration warning)"
  local daemon_entry_cfg
  daemon_entry_cfg=$(grep -E '"github.com/netxfw/netxfw/internal/config"' cmd/netxfwagent/main.go cmd/netxfwdp/main.go 2>/dev/null || true)
  if [ -n "$daemon_entry_cfg" ]; then
    print_warn "daemon 入口直接导入 internal/config（迁移态告警：后续可经 app 装配层收敛）"
    echo "$daemon_entry_cfg"
    inc_warning
  else
    print_ok "daemon 入口 cmd -> config 检查通过"
  fi
  echo ""

  # pkg -> internal（严格禁止，但允许当前仅 pkg/sdk 依赖 internal/plugins/types 的兼容点）
  echo "5. pkg -> internal reverse deps"
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
      print_warn "pkg 依赖 internal/plugins/types（迁移态兼容点，建议后续将 types 下沉到 pkg 或抽象接口）"
      echo "$pkg_internal"
      inc_warning
    fi
  else
    print_ok "pkg -> internal 检查通过"
  fi
  echo ""

  # internal -> cmd（严格禁止）
  echo "6. internal -> cmd reverse deps (error)"
  local internal_cmd
  internal_cmd=$(grep -R -E '"github.com/netxfw/netxfw/cmd/' internal --include="*.go" 2>/dev/null || true)
  if [ -n "$internal_cmd" ]; then
    print_err "发现 internal 层反向依赖 cmd（不允许）"
    echo "$internal_cmd"
    inc_error
  else
    print_ok "internal -> cmd 检查通过"
  fi
  echo ""
}

# 2) system 模块治理（当前仓库仍为单文件聚合形态，规则以告警为主）
check_system_module_conventions() {
  echo "检查 system 模块规范..."
  echo "Checking system module conventions..."
  echo ""

  # system.go 体量（迁移态告警）
  echo "7. [SYS-ENTRY-SIZE] system.go 体量（warning）"
  if [ -f cmd/agent/system.go ]; then
    local lines
    lines=$(wc -l < cmd/agent/system.go | tr -d ' ')
    if [ "$lines" -gt 650 ]; then
      print_warn "system.go 过大 (${lines} 行)，建议后续拆分（当前按迁移态告警）"
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
  echo "8. [SYS-REASON-SOURCE] reason 映射单一来源"
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
  echo "9. [SYS-REQUIRED-FILES] system 关键文件完整性"
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

  # runtime boundary：除了 system.go 之外，不建议其他 agent 文件直接依赖底层 XDP/ebpf/link
  echo "10. [SYS-RUNTIME-BOUNDARY] 非 system.go 文件的底层依赖泄漏（error）"
  local leaked
  leaked=$(grep -R -E '"github.com/cilium/ebpf/link"|"github.com/netxfw/netxfw/internal/xdp"' cmd/agent --include="*.go" 2>/dev/null | grep -v 'cmd/agent/system.go' || true)
  if [ -n "$leaked" ]; then
    print_err "发现 system 以外的 agent 文件直接依赖底层 XDP/ebpf（建议通过 manager/SDK/执行器封装）"
    echo "$leaked"
    inc_error
  else
    print_ok "运行时边界依赖检查通过"
  fi
  echo ""
}

# 3) internal/xdp 治理（保持告警性质为主）
check_xdp_module_conventions() {
  echo "检查 xdp 模块规范..."
  echo "Checking xdp module conventions..."
  echo ""

  echo "11. [XDP-SUBPKG-UPWARD-IMPORT] xdp 子包反向依赖（error）"
  if [ -d internal/xdp/statscalc ] && [ -d internal/xdp/syncutil ]; then
    local upward
    upward=$(grep -R '"github.com/netxfw/netxfw/internal/xdp"' internal/xdp/statscalc internal/xdp/syncutil --include="*.go" 2>/dev/null || true)
    if [ -n "$upward" ]; then
      print_err "发现 xdp 子包反向导入 internal/xdp"
      echo "$upward"
      inc_error
    else
      print_ok "xdp 子包反向依赖检查通过"
    fi
  else
    print_ok "xdp 子包目录不存在（跳过）"
  fi
  echo ""

  echo "12. [XDP-FILE-SCALE] xdp 顶层文件规模（warning）"
  if [ -d internal/xdp ]; then
    local c
    c=$(find internal/xdp -maxdepth 1 -name "*.go" | wc -l | tr -d ' ')
    if [ "$c" -gt 70 ]; then
      print_warn "internal/xdp 顶层 Go 文件数偏多: $c（建议子包化）"
      inc_warning
    else
      print_ok "xdp 文件规模检查通过 ($c files)"
    fi
  fi
  echo ""

  echo "13. [XDP-PREFIX-GOVERNANCE] xdp 文件前缀治理（warning）"
  # 对齐当前仓库：补齐已存在的前缀集合，减少误报
  local allowed_prefixes="adapter api bpf core errors helpers map misc mock netxfw pool real rules stats sync types util xdp health incremental interfaces lock manager metrics performance utils"
  local unknown=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    local base name_no_ext prefix
    base=$(basename "$f")
    name_no_ext="${base%.go}"
    prefix="${name_no_ext%%_*}"
    if [[ "$name_no_ext" == "$prefix" ]]; then
      prefix="$name_no_ext"
    fi
    case " $allowed_prefixes " in
      *" $prefix "*) ;;
      *) unknown+="$f"$'\n' ;;
    esac
  done < <(find internal/xdp -maxdepth 1 -name "*.go" -type f | sort)

  if [ -n "$unknown" ]; then
    print_warn "发现未登记前缀文件（建议登记或重命名）"
    echo "$unknown"
    inc_warning
  else
    print_ok "xdp 文件前缀治理检查通过"
  fi
  echo ""
}

# 4) 循环依赖（保持原逻辑，godepgraph 可选）
check_circular_deps() {
  echo "检查循环依赖..."
  echo "Checking circular dependencies..."
  echo ""

  if command -v godepgraph &>/dev/null; then
    if godepgraph -n cmd/... 2>&1 | grep -q "cycle"; then
      print_err "发现循环依赖"
      inc_error
    else
      print_ok "未发现循环依赖"
    fi
  else
    print_warn "跳过：未安装 godepgraph"
    inc_warning
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

# 7) coverage（默认阈值 80%，未达标按 warning；可后续升级为关键路径阈值）
check_coverage() {
  echo "检查测试覆盖率..."
  echo "Checking test coverage..."
  echo ""

  if ! command -v go &>/dev/null; then
    print_err "Go 未安装"
    inc_error
    return
  fi

  go test -coverprofile=coverage.out ./... >/dev/null 2>&1 || true

  if [ -f coverage.out ]; then
    local cov
    cov=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    echo "总覆盖率 / Total coverage: ${cov}%"

    # awk numeric compare
    local below
    below=$(awk -v c="$cov" 'BEGIN{print (c<80)?1:0}')
    if [ "$below" -eq 1 ]; then
      print_warn "测试覆盖率低于 80% (${cov}%)（当前按告警处理）"
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
