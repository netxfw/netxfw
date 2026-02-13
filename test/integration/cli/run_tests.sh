#!/bin/bash
set -e

# Define paths
# 定义路径
BASE_DIR=$(dirname "$0")/../../..
BIN_PATH="$BASE_DIR/netxfw"
export NETXFW_BIN="$BIN_PATH"
IMPORT_FILE="$(dirname "$0")/import_test.txt"

echo "=== Building netxfw for testing ==="
# 为测试构建 netxfw
cd "$BASE_DIR"
make build
cd - > /dev/null

if [ ! -f "$BIN_PATH" ]; then
    echo "❌ Binary not found at $BIN_PATH"
    exit 1
fi

echo "=== Running Go Verification Script (List/Remove) ==="
# 运行 Go 验证脚本 (List/Remove)
go run "$(dirname "$0")/verify_fix.go"

echo ""
echo "=== Running Shell Verification (Import/Sync) ==="
# 运行 Shell 验证 (Import/Sync)

# Create dummy import file
# 创建虚拟导入文件
echo "Creating dummy import file..."
echo "192.0.2.200" > "$IMPORT_FILE"
echo "2001:db8::200" >> "$IMPORT_FILE"

# Test Import
# 测试导入
echo "[Test 3] Rule Import"
"$BIN_PATH" rule import deny "$IMPORT_FILE"
OUT=$("$BIN_PATH" rule list deny)
if echo "$OUT" | grep -q "192.0.2.200" && echo "$OUT" | grep -q "2001:db8::200"; then
    echo "✅ Import successful: IPs found in blacklist."
else
    echo "❌ Import failed. Output:"
    echo "$OUT"
fi

# Test Sync
# 测试同步
echo ""
echo "[Test 4] System Sync"
"$BIN_PATH" system sync to-config
if [ $? -eq 0 ]; then
    echo "✅ Sync to-config executed successfully."
else
    echo "❌ Sync to-config failed."
fi

# Cleanup
# 清理
"$BIN_PATH" rule remove deny 192.0.2.200 > /dev/null 2>&1
"$BIN_PATH" rule remove deny 2001:db8::200 > /dev/null 2>&1
# Also cleanup verify_fix.go leftovers if any
# 清理 verify_fix.go 遗留的测试数据
"$BIN_PATH" rule remove deny 192.0.2.100 > /dev/null 2>&1

echo ""
echo "=== All CLI Tests Completed ==="
