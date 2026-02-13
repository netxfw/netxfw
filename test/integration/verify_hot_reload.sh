#!/bin/bash
set -e

NETXFW_BIN="/root/netxfw/netxfw"
CONFIG_FILE="/etc/netxfw/config.yaml"

# Ensure config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found: $CONFIG_FILE"
    exit 1
fi

echo "1. Initial Load..."
# We ignore errors here because it might already be loaded or have some issues, 
# but we want to test the reload logic primarily.
$NETXFW_BIN system load > /dev/null 2>&1 || true

echo "2. Testing Incremental Reload (Capacity Unchanged)..."
# Capture stderr because log.Println goes there
OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity unchanged"; then
    echo "PASS: Incremental reload detected."
else
    echo "FAIL: Expected 'Capacity unchanged', got:"
    echo "$OUTPUT"
    exit 1
fi

echo "3. Testing Full Reload (Capacity Changed)..."
# Modify config: change conntrack capacity
sed -i 's/conntrack: 100000/conntrack: 100001/' $CONFIG_FILE

OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity changed"; then
    echo "PASS: Full reload detected."
else
    echo "FAIL: Expected 'Capacity changed', got:"
    echo "$OUTPUT"
    # Restore config before exit
    sed -i 's/conntrack: 100001/conntrack: 100000/' $CONFIG_FILE
    exit 1
fi

# Restore config
sed -i 's/conntrack: 100001/conntrack: 100000/' $CONFIG_FILE

echo "4. Testing Full Reload again (Restored)..."
OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity changed"; then
    echo "PASS: Full reload detected (revert capacity)."
else
    echo "FAIL: Expected 'Capacity changed' (revert), got:"
    echo "$OUTPUT"
    exit 1
fi

echo "5. Testing Incremental Reload again (Stable)..."
OUTPUT=$($NETXFW_BIN system reload 2>&1)
if echo "$OUTPUT" | grep -q "Capacity unchanged"; then
    echo "PASS: Incremental reload detected after restore."
else
    echo "FAIL: Expected 'Capacity unchanged' after restore, got:"
    echo "$OUTPUT"
    exit 1
fi

echo "ALL TESTS PASSED"
