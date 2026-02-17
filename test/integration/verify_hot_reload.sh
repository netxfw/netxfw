#!/bin/bash
#
# verify_hot_reload.sh - Test script for hot reload functionality.
# verify_hot_reload.sh - 热重载功能的测试脚本。
#
# This script tests the incremental and full reload capabilities of netxfw.
# 此脚本测试 netxfw 的增量和完整重载能力。
#

set -e

# Color codes for output.
# 输出的颜色代码。
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color / 无颜色

# Binary and config paths.
# 二进制文件和配置文件路径。
NETXFW_BIN="/root/netxfw/netxfw"
CONFIG_FILE="/etc/netxfw/config.yaml"

# print_result prints test result with color.
# print_result 打印带颜色的测试结果。
print_result() {
    local passed=$1
    local message=$2
    if [ "$passed" -eq 0 ]; then
        echo -e "${GREEN}PASS${NC}: $message"
    else
        echo -e "${RED}FAIL${NC}: $message"
    fi
}

# cleanup restores the config file to original state.
# cleanup 将配置文件恢复到原始状态。
cleanup() {
    if [ -f "$CONFIG_FILE" ]; then
        sed -i 's/conntrack: 100001/conntrack: 100000/' "$CONFIG_FILE" 2>/dev/null || true
    fi
}

# Register cleanup on exit.
# 退出时注册清理函数。
trap cleanup EXIT

# Ensure config file exists.
# 确保配置文件存在。
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error${NC}: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Ensure binary exists.
# 确保二进制文件存在。
if [ ! -x "$NETXFW_BIN" ]; then
    echo -e "${RED}Error${NC}: Binary not found or not executable: $NETXFW_BIN"
    exit 1
fi

echo -e "${YELLOW}1. Initial Load...${NC}"
# We ignore errors here because it might already be loaded or have some issues,
# but we want to test the reload logic primarily.
# 我们在这里忽略错误，因为它可能已经加载或存在一些问题，
# 但我们主要想测试重载逻辑。
$NETXFW_BIN system load > /dev/null 2>&1 || true

echo -e "${YELLOW}2. Testing Incremental Reload (Capacity Unchanged)...${NC}"
# Capture stderr because log.Println goes there.
# 捕获 stderr，因为 log.Println 输出到那里。
OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity unchanged"; then
    print_result 0 "Incremental reload detected."
else
    print_result 1 "Expected 'Capacity unchanged', got:"
    echo "$OUTPUT"
    exit 1
fi

echo -e "${YELLOW}3. Testing Full Reload (Capacity Changed)...${NC}"
# Modify config: change conntrack capacity.
# 修改配置：更改 conntrack 容量。
sed -i 's/conntrack: 100000/conntrack: 100001/' "$CONFIG_FILE"

OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity changed"; then
    print_result 0 "Full reload detected."
else
    print_result 1 "Expected 'Capacity changed', got:"
    echo "$OUTPUT"
    exit 1
fi

echo -e "${YELLOW}4. Testing Full Reload again (Restored)...${NC}"
# Restore config.
# 恢复配置。
sed -i 's/conntrack: 100001/conntrack: 100000/' "$CONFIG_FILE"

OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity changed"; then
    print_result 0 "Full reload detected (revert capacity)."
else
    print_result 1 "Expected 'Capacity changed' (revert), got:"
    echo "$OUTPUT"
    exit 1
fi

echo -e "${YELLOW}5. Testing Incremental Reload again (Stable)...${NC}"
OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity unchanged"; then
    print_result 0 "Incremental reload detected after restore."
else
    print_result 1 "Expected 'Capacity unchanged' after restore, got:"
    echo "$OUTPUT"
    exit 1
fi

echo -e "\n${GREEN}ALL TESTS PASSED${NC}"
