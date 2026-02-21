#!/bin/bash

# verify_web_cli.sh
# Tests the netxfw web command

set -e

# Create temporary config file
CONFIG_FILE=$(mktemp)
echo "Creating temp config: $CONFIG_FILE"

cleanup() {
    rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

# 1. Test DISABLED configuration
cat > "$CONFIG_FILE" <<EOF
web:
  enabled: false
EOF

echo "Testing DISABLED config..."
OUTPUT=$(./netxfw web --config "$CONFIG_FILE")
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Web interface is DISABLED"; then
    echo "✅ PASSED: Detected disabled web interface"
else
    echo "❌ FAILED: Did not detect disabled web interface"
    exit 1
fi

# 2. Test ENABLED configuration
cat > "$CONFIG_FILE" <<EOF
web:
  enabled: true
  port: 8080
  token: "test-token"
EOF

echo "Testing ENABLED config..."
OUTPUT=$(./netxfw web --config "$CONFIG_FILE")
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Web interface is ENABLED"; then
    echo "✅ PASSED: Detected enabled web interface"
else
    echo "❌ FAILED: Did not detect enabled web interface"
    exit 1
fi

if echo "$OUTPUT" | grep -q "URL: http://localhost:8080"; then
    echo "✅ PASSED: Correct port detected"
else
    echo "❌ FAILED: Incorrect port detected"
    exit 1
fi

if echo "$OUTPUT" | grep -q "Token: test-token"; then
    echo "✅ PASSED: Correct token detected"
else
    echo "❌ FAILED: Incorrect token detected"
    exit 1
fi

echo "🎉 All web CLI tests passed!"
