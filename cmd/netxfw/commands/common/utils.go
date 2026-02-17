package common

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/livp123/netxfw/internal/config"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/utils/logger"
	"github.com/livp123/netxfw/internal/xdp"
	"github.com/livp123/netxfw/pkg/sdk"
)

var (
	// MockSDK allows tests to inject a mock SDK
	// MockSDK 允许测试注入 Mock SDK
	MockSDK *sdk.SDK
)

// GetSDK returns an initialized SDK connected to the pinned maps.
// GetSDK 返回一个连接到固定 Map 的初始化 SDK。
func GetSDK() (*sdk.SDK, error) {
	if MockSDK != nil {
		return MockSDK, nil
	}
	pinPath := config.GetPinPath()
	mgr, err := xdp.NewManagerFromPins(pinPath, logger.Get(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager from %s: %w", pinPath, err)
	}
	// Use NewAdapter to ensure interface compliance
	adapter := xdp.NewAdapter(mgr)
	return sdk.NewSDK(adapter), nil
}

// EnsureStandaloneMode ensures that the application is running in standalone mode.
// EnsureStandaloneMode 确保应用程序以独立模式运行。
var EnsureStandaloneMode = func() {
	if MockSDK != nil {
		return
	}
	if os.Geteuid() != 0 {
		fmt.Println("❌ This command must be run as root.")
		os.Exit(1)
	}
}

// AskConfirmation prompts the user for confirmation.
// AskConfirmation 提示用户确认。
func AskConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// ImportLockListFromFile imports IPs from a file to the blacklist.
func ImportLockListFromFile(s *sdk.SDK, path string) error {
	cfgPath := config.GetConfigPath()
	cfg, err := types.LoadGlobalConfig(cfgPath)
	persistFile := ""
	if err == nil {
		persistFile = cfg.Base.LockListFile
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if persistFile != "" {
				if err := s.Blacklist.AddWithFile(line, persistFile); err != nil {
					fmt.Printf("⚠️ Failed to add %s: %v\n", line, err)
				} else {
					fmt.Printf("✅ Added %s to blacklist\n", line)
				}
			} else {
				if err := s.Blacklist.Add(line); err != nil {
					fmt.Printf("⚠️ Failed to add %s: %v\n", line, err)
				} else {
					fmt.Printf("✅ Added %s to blacklist\n", line)
				}
			}
		}
	}
	return scanner.Err()
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
func ImportWhitelistFromFile(s *sdk.SDK, path string) error {
	// Whitelist usually doesn't have a separate persistence file in the same way,
	// or it relies on config.yaml syncing.
	// But AddWithFile is not available for WhitelistAPI.
	// So we just Add(), and user should run 'sync to-config' to persist if needed.

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP or IP:Port
			parts := strings.Split(line, ":")
			ip := parts[0]
			var port uint16
			if len(parts) > 1 {
				p, _ := strconv.Atoi(parts[1])
				port = uint16(p)
			}

			if err := s.Whitelist.Add(ip, port); err != nil {
				fmt.Printf("⚠️ Failed to add %s: %v\n", line, err)
			} else {
				fmt.Printf("✅ Added %s to whitelist\n", line)
			}
		}
	}
	return scanner.Err()
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
func ImportIPPortRulesFromFile(s *sdk.SDK, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Format: IP:Port:Action (allow/deny)
			parts := strings.Split(line, ":")
			if len(parts) < 3 {
				fmt.Printf("⚠️ Invalid format: %s (expected IP:Port:Action)\n", line)
				continue
			}
			ip := parts[0]
			port, _ := strconv.Atoi(parts[1])
			actionStr := strings.ToLower(parts[2])
			action := uint8(2) // Deny default
			if actionStr == "allow" {
				action = 1
			}

			if err := s.Rule.AddIPPortRule(ip, uint16(port), action); err != nil {
				fmt.Printf("⚠️ Failed to add rule %s: %v\n", line, err)
			} else {
				fmt.Printf("✅ Added rule %s\n", line)
			}
		}
	}
	return scanner.Err()
}
