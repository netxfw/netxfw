package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runCmd(args ...string) string {
	cmd := exec.Command("/root/netxfw/bin/netxfw", args...)
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
	fmt.Println("\n[Test 1] Rule List Deny Display")
	// Ensure clean state
	runCmd("rule", "allow", testIP)

	// Add to deny
	runCmd("rule", "deny", testIP)

	// List
	out := runCmd("rule", "list", "deny")
	if strings.Contains(out, "Blacklist Rules") && strings.Contains(out, testIP) {
		fmt.Println("✅ 'rule list deny' correctly shows Blacklist header and IP.")
	} else {
		fmt.Printf("❌ 'rule list deny' failed. Output:\n%s\n", out)
	}

	if strings.Contains(out, "Whitelist Rules") {
		fmt.Println("❌ 'rule list deny' incorrectly shows Whitelist header.")
	} else {
		fmt.Println("✅ 'rule list deny' does NOT show Whitelist header.")
	}

	// 2. Test Rule Remove Persistence
	fmt.Println("\n[Test 2] Rule Remove Persistence")

	// Check file before remove
	content, _ := os.ReadFile("/etc/netxfw/rules.deny.txt")
	if !strings.Contains(string(content), testIP) {
		fmt.Println("⚠️  Warning: IP not found in deny file after add (might be using config.yaml persistence or not enabled). Checking config.yaml...")
		// Actually the tool defaults to rules.deny.txt if configured. Let's assume default config for now.
	}

	// Remove
	fmt.Printf("Removing %s...\n", testIP)
	runCmd("rule", "allow", testIP) // allow removes from blacklist

	// Check List
	out = runCmd("rule", "list", "deny")
	if strings.Contains(out, testIP) {
		fmt.Println("❌ IP still in BPF map after remove.")
	} else {
		fmt.Println("✅ IP removed from BPF map.")
	}

	// Check File
	// We need to check where it persists. Based on previous code, it checks globalCfg.Base.LockListFile
	// Let's check both likely locations just to be sure
	contentDeny, _ := os.ReadFile("/etc/netxfw/rules.deny.txt")
	if strings.Contains(string(contentDeny), testIP) {
		fmt.Println("❌ IP still in /etc/netxfw/rules.deny.txt after remove.")
	} else {
		fmt.Println("✅ IP removed from /etc/netxfw/rules.deny.txt.")
	}

	fmt.Println("\n=== Test Complete ===")
}
