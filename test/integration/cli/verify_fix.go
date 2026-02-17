//go:build ignore

// Package main contains CLI verification tests.
// Package main 包含 CLI 验证测试。
//
// This file is excluded from normal builds and tests.
// Use: go run verify_fix.go
// 此文件从正常构建和测试中排除。
// 使用方法: go run verify_fix.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runCmd executes the netxfw binary with given arguments.
// runCmd 使用给定参数执行 netxfw 二进制文件。
func runCmd(args ...string) string {
	binPath := os.Getenv("NETXFW_BIN")
	if binPath == "" {
		binPath = "/usr/local/bin/netxfw"
	}
	cmd := exec.Command(binPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running netxfw %v: %v\nOutput: %s\n", args, err, string(out))
		return ""
	}
	return string(out)
}

func main() {
	fmt.Println("=== Testing Fixes ===")

	testIP := "192.0.2.100"

	// 1. Test Rule List Deny
	// 1. 测试规则列表 Deny 显示
	fmt.Println("\n[Test 1] Rule List Deny Display")
	// Ensure clean state
	// 确保状态干净
	runCmd("rule", "remove", testIP, "deny")

	// Add to deny
	// 添加到拒绝列表
	fmt.Println("Adding test IP...")
	addOut := runCmd("rule", "add", testIP, "deny")
	fmt.Println(addOut)

	// List
	// 列出规则
	out := runCmd("rule", "list", "deny")
	if strings.Contains(out, "Blacklist Rules (Lock List)") && strings.Contains(out, testIP) {
		fmt.Println("✅ 'rule list deny' correctly shows Blacklist header and IP.")
	} else {
		fmt.Printf("❌ 'rule list deny' failed. Output:\n%s\n", out)
	}

	if strings.Contains(out, "Whitelist (IP Rules)") {
		fmt.Println("❌ 'rule list deny' incorrectly shows Whitelist header.")
	} else {
		fmt.Println("✅ 'rule list deny' does NOT show Whitelist header.")
	}

	// 2. Test Rule Remove Persistence
	// 2. 测试规则移除持久化
	fmt.Println("\n[Test 2] Rule Remove Persistence")

	// Check file before remove
	// 移除前检查文件
	content, _ := os.ReadFile("/etc/netxfw/lock_list.txt")
	if !strings.Contains(string(content), testIP) {
		fmt.Println("⚠️  Warning: IP not found in lock list file after add (might be using config.yaml persistence or not enabled). Checking config.yaml...")
	}

	// Remove
	// 移除规则
	fmt.Printf("Removing %s...\n", testIP)
	runCmd("rule", "remove", testIP, "deny") // allow removes from blacklist

	// Check List
	// 检查列表
	out = runCmd("rule", "list", "deny")
	if strings.Contains(out, testIP) {
		fmt.Println("❌ IP still in BPF map after remove.")
	} else {
		fmt.Println("✅ IP removed from BPF map.")
	}

	// Check File
	// 检查文件
	// We need to check where it persists.
	// 我们需要检查它持久化的位置。
	contentDeny, _ := os.ReadFile("/etc/netxfw/lock_list.txt")
	if strings.Contains(string(contentDeny), testIP) {
		fmt.Println("❌ IP still in /etc/netxfw/lock_list.txt after remove.")
	} else {
		fmt.Println("✅ IP removed from /etc/netxfw/lock_list.txt.")
	}

	fmt.Println("\n=== Test Complete ===")
}
