package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/netxfw/netxfw/internal/utils/iputil"
)

// generateRandomToken generates a random hex string of given length.
// generateRandomToken 生成给定长度的随机十六进制字符串。
func generateRandomToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "netxfw_default_token_please_change"
	}
	return hex.EncodeToString(b)
}

// parseIPPortAction parses an input string into IP, port and action.
// parseIPPortAction 将输入字符串解析为 IP、端口和动作。
func parseIPPortAction(input string) (string, uint16, uint8, error) {
	// Format: IP:Port:Action or [IP]:Port:Action
	// 格式: IP:Port:Action 或 [IP]:Port:Action
	// Action: allow (1) or deny (2)

	// Use iputil to parse IP and Port first
	// 首先使用 iputil 解析 IP 和端口
	// iputil.ParseIPPort handles:
	// 1.2.3.4:80
	// [2001:db8::1]:80
	// 2001:db8::1:80 (might be tricky if action is appended, let's check)

	// iputil.ParseIPPort expects "host:port".
	// If the input has ":action" at the end, SplitHostPort might fail or return the action as port if not careful.
	// However, for "1.2.3.4:80:allow", SplitHostPort("1.2.3.4:80:allow") -> host="1.2.3.4:80", port="allow" (which fails atoi)
	// OR it errors out "too many colons".

	// So we need to strip the action part first.
	// 我们需要先剥离 action 部分。

	lastColon := strings.LastIndex(input, ":")
	if lastColon == -1 {
		return "", 0, 0, fmt.Errorf("invalid format")
	}

	// Check if the last part is a valid action
	// 检查最后一部分是否为有效动作
	suffix := input[lastColon+1:]
	var action uint8 = 2 // Default deny
	hasAction := false

	if suffix == "allow" {
		action = 1
		hasAction = true
	} else if suffix == "deny" {
		action = 2
		hasAction = true
	}

	var ipPortStr string
	if hasAction {
		ipPortStr = input[:lastColon]
	} else {
		// No explicit action, assume the last part is the port
		// 没有显式动作，假设最后一部分是端口
		ipPortStr = input
	}

	host, port, err := iputil.ParseIPPort(ipPortStr)
	if err != nil {
		return "", 0, 0, err
	}

	// Normalize IPv6: remove brackets if present (ParseIPPort returns host without brackets)
	// 标准化 IPv6：如果有方括号则移除（ParseIPPort 返回的主机不带方括号）
	// iputil.ParseIPPort already returns clean host string.

	return host, port, action, nil
}
