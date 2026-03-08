#!/bin/bash
#
# Release Acceptance Checklist / 发布验收检查清单
# This script performs manual verification tests before release.
# 此脚本在发布前执行手动验证测试。
#
# Usage / 用法:
#   ./scripts/release-checklist.sh [binary_path]
#
# Note: These tests are for release verification only, not for CI automation.
# 注意：这些测试仅用于发布验证，不用于 CI 自动化。
#

set -e

# Colors for output / 输出颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color / 无颜色

# Test counters / 测试计数器
PASSED=0
FAILED=0
TOTAL=0

# Binary path / 二进制文件路径
BINARY="${1:-./netxfw}"

# Print header / 打印标题
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Release Acceptance Checklist${NC}"
    echo -e "${BLUE}  发布验收检查清单${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "Binary / 二进制文件: ${YELLOW}${BINARY}${NC}"
    echo -e "Date / 日期: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
}

# Print test result / 打印测试结果
print_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    TOTAL=$((TOTAL + 1))
    
    if [ "$result" = "PASS" ]; then
        PASSED=$((PASSED + 1))
        echo -e "${GREEN}[✓]${NC} ${test_name}"
    else
        FAILED=$((FAILED + 1))
        echo -e "${RED}[✗]${NC} ${test_name}"
        [ -n "$details" ] && echo -e "    ${RED}Details: ${details}${NC}"
    fi
}

# Print section header / 打印章节标题
print_section() {
    echo ""
    echo -e "${YELLOW}>>> $1${NC}"
    echo -e "${YELLOW}    $2${NC}"
}

# Check if binary exists / 检查二进制文件是否存在
check_binary() {
    print_section "Binary Check" "二进制文件检查"
    
    if [ -x "$BINARY" ]; then
        print_result "Binary exists and is executable / 二进制文件存在且可执行" "PASS"
        local size=$(ls -lh "$BINARY" | awk '{print $5}')
        echo -e "    Size / 大小: ${size}"
    else
        print_result "Binary exists and is executable / 二进制文件存在且可执行" "FAIL" "Binary not found: $BINARY"
        exit 1
    fi
}

# Test basic commands / 测试基本命令
test_basic_commands() {
    print_section "Basic Commands" "基本命令测试"
    
    # Test help / 测试帮助
    if "$BINARY" --help >/dev/null 2>&1; then
        print_result "Main help command / 主命令帮助" "PASS"
    else
        print_result "Main help command / 主命令帮助" "FAIL"
    fi
    
    # Test version (if available) / 测试版本（如果可用）
    if "$BINARY" version >/dev/null 2>&1; then
        print_result "Version command / 版本命令" "PASS"
    else
        print_result "Version command / 版本命令" "SKIP (optional / 可选)"
    fi
}

# Test rule commands / 测试规则命令
test_rule_commands() {
    print_section "Rule Commands" "规则命令测试"
    
    # Test rule help / 测试规则帮助
    if "$BINARY" rule --help >/dev/null 2>&1; then
        print_result "Rule help command / 规则帮助命令" "PASS"
    else
        print_result "Rule help command / 规则帮助命令" "FAIL"
    fi
    
    # Test rule list help / 测试规则列表帮助
    if "$BINARY" rule list --help >/dev/null 2>&1; then
        print_result "Rule list help / 规则列表帮助" "PASS"
    else
        print_result "Rule list help / 规则列表帮助" "FAIL"
    fi
    
    # Test rule import help / 测试规则导入帮助
    if "$BINARY" rule import --help >/dev/null 2>&1; then
        print_result "Rule import help / 规则导入帮助" "PASS"
    else
        print_result "Rule import help / 规则导入帮助" "FAIL"
    fi
    
    # Test rule export help / 测试规则导出帮助
    if "$BINARY" rule export --help >/dev/null 2>&1; then
        print_result "Rule export help / 规则导出帮助" "PASS"
    else
        print_result "Rule export help / 规则导出帮助" "FAIL"
    fi
}

# Test completion commands / 测试补全命令
test_completion_commands() {
    print_section "Completion Commands" "补全命令测试"
    
    # Test completion help / 测试补全帮助
    if "$BINARY" completion --help >/dev/null 2>&1; then
        print_result "Completion help / 补全帮助" "PASS"
    else
        print_result "Completion help / 补全帮助" "FAIL"
    fi
    
    # Test bash completion / 测试 bash 补全
    if "$BINARY" completion bash >/dev/null 2>&1; then
        print_result "Bash completion generation / Bash 补全生成" "PASS"
    else
        print_result "Bash completion generation / Bash 补全生成" "FAIL"
    fi
    
    # Test zsh completion / 测试 zsh 补全
    if "$BINARY" completion zsh >/dev/null 2>&1; then
        print_result "Zsh completion generation / Zsh 补全生成" "PASS"
    else
        print_result "Zsh completion generation / Zsh 补全生成" "FAIL"
    fi
    
    # Test fish completion / 测试 fish 补全
    if "$BINARY" completion fish >/dev/null 2>&1; then
        print_result "Fish completion generation / Fish 补全生成" "PASS"
    else
        print_result "Fish completion generation / Fish 补全生成" "FAIL"
    fi
}

# Test system commands / 测试系统命令
test_system_commands() {
    print_section "System Commands" "系统命令测试"
    
    # Test system help / 测试系统帮助
    if "$BINARY" system --help >/dev/null 2>&1; then
        print_result "System help / 系统帮助" "PASS"
    else
        print_result "System help / 系统帮助" "FAIL"
    fi
    
    # Test system status help / 测试系统状态帮助
    if "$BINARY" system status --help >/dev/null 2>&1; then
        print_result "System status help / 系统状态帮助" "PASS"
    else
        print_result "System status help / 系统状态帮助" "FAIL"
    fi
}

# Test allow/deny commands / 测试允许/拒绝命令
test_allow_deny_commands() {
    print_section "Allow/Deny Commands" "允许/拒绝命令测试"
    
    # Test allow help / 测试允许帮助
    if "$BINARY" allow --help >/dev/null 2>&1; then
        print_result "Allow help / 允许帮助" "PASS"
    else
        print_result "Allow help / 允许帮助" "FAIL"
    fi
    
    # Test deny help / 测试拒绝帮助
    if "$BINARY" deny --help >/dev/null 2>&1; then
        print_result "Deny help / 拒绝帮助" "PASS"
    else
        print_result "Deny help / 拒绝帮助" "FAIL"
    fi
}

# Test conntrack commands / 测试连接跟踪命令
test_conntrack_commands() {
    print_section "Conntrack Commands" "连接跟踪命令测试"
    
    # Test conntrack help / 测试连接跟踪帮助
    if "$BINARY" conntrack --help >/dev/null 2>&1; then
        print_result "Conntrack help / 连接跟踪帮助" "PASS"
    else
        print_result "Conntrack help / 连接跟踪帮助" "FAIL"
    fi
}

# Test dynamic commands / 测试动态命令
test_dynamic_commands() {
    print_section "Dynamic Commands" "动态命令测试"
    
    # Test dynamic help / 测试动态帮助
    if "$BINARY" dynamic --help >/dev/null 2>&1; then
        print_result "Dynamic help / 动态帮助" "PASS"
    else
        print_result "Dynamic help / 动态帮助" "FAIL"
    fi
}

# Print summary / 打印摘要
print_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Summary / 摘要${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "Total tests / 总测试数: ${TOTAL}"
    echo -e "${GREEN}Passed / 通过: ${PASSED}${NC}"
    echo -e "${RED}Failed / 失败: ${FAILED}${NC}"
    echo ""
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All acceptance tests passed!${NC}"
        echo -e "${GREEN}✓ 所有验收测试通过！${NC}"
        echo ""
        echo -e "${YELLOW}Ready for release. / 准备发布。${NC}"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Please review before release.${NC}"
        echo -e "${RED}✗ 部分测试失败，发布前请检查。${NC}"
        exit 1
    fi
}

# Main function / 主函数
main() {
    print_header
    check_binary
    test_basic_commands
    test_rule_commands
    test_completion_commands
    test_system_commands
    test_allow_deny_commands
    test_conntrack_commands
    test_dynamic_commands
    print_summary
}

main "$@"
