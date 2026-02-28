package common

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/netxfw/netxfw/internal/config"
	"github.com/netxfw/netxfw/internal/plugins/types"
	"github.com/netxfw/netxfw/internal/utils/logger"
	"github.com/netxfw/netxfw/internal/xdp"
	"github.com/netxfw/netxfw/pkg/sdk"
)

var (
	// MockSDK allows tests to inject a mock SDK
	// MockSDK 允许测试注入 Mock SDK
	MockSDK *sdk.SDK

	// mockSDKMutex protects MockSDK from concurrent access
	// mockSDKMutex 保护 MockSDK 免受并发访问
	mockSDKMutex sync.RWMutex

	// realSDK caches the real SDK instance to avoid recreating
	// realSDK 缓存真实 SDK 实例以避免重复创建
	realSDK    *sdk.SDK
	realSDKMux sync.Mutex
)

// GetSDK returns an initialized SDK connected to the pinned maps.
// GetSDK 返回一个连接到固定 Map 的初始化 SDK。
func GetSDK() (*sdk.SDK, error) {
	// First check for mock SDK with read lock
	// 首先使用读锁检查 mock SDK
	mockSDKMutex.RLock()
	if MockSDK != nil {
		defer mockSDKMutex.RUnlock()
		return MockSDK, nil
	}
	mockSDKMutex.RUnlock()

	// Use double-checked locking for real SDK to avoid race condition
	// 使用双重检查锁定真实 SDK 以避免竞态条件
	realSDKMux.Lock()
	defer realSDKMux.Unlock()

	// Check again in case another goroutine created it while we waited for lock
	// 再次检查，以防其他 goroutine 在我们等待锁时创建了它
	if realSDK != nil {
		return realSDK, nil
	}

	pinPath := config.GetPinPath()
	mgr, err := xdp.NewManagerFromPins(pinPath, logger.Get(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to load XDP manager from %s: %w", pinPath, err)
	}
	// Use NewAdapter to ensure interface compliance
	adapter := xdp.NewAdapter(mgr)
	realSDK = sdk.NewSDK(adapter)
	return realSDK, nil
}

// SetMockSDK sets the mock SDK for testing (thread-safe)
// SetMockSDK 设置用于测试的 Mock SDK（线程安全）
func SetMockSDK(mock *sdk.SDK) {
	mockSDKMutex.Lock()
	defer mockSDKMutex.Unlock()
	MockSDK = mock
}

// EnsureStandaloneMode ensures that the application is running in standalone mode.
// EnsureStandaloneMode 确保应用程序以独立模式运行。
var EnsureStandaloneMode = func() {
	if MockSDK != nil {
		return
	}
	if os.Geteuid() != 0 {
		fmt.Println("[ERROR] This command must be run as root.")
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
	// 验证文件路径和大小
	// Validate file path and size
	safePath, err := ValidateImportFile(path)
	if err != nil {
		return err
	}

	cfgPath := config.GetConfigPath()
	cfg, cfgErr := types.LoadGlobalConfig(cfgPath)
	persistFile := ""
	if cfgErr == nil {
		persistFile = cfg.Base.LockListFile
	}

	file, err := os.Open(safePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// 验证 IP 格式
			// Validate IP format
			if err := ValidateIP(line); err != nil {
				fmt.Printf("[WARN] Invalid IP format: %s: %v\n", line, err)
				continue
			}
			if persistFile != "" {
				if err := s.Blacklist.AddWithFile(line, persistFile); err != nil {
					fmt.Printf("[WARN] Failed to add %s: %v\n", line, err)
				} else {
					fmt.Printf("[OK] Added %s to blacklist\n", line)
				}
			} else {
				if err := s.Blacklist.Add(line); err != nil {
					fmt.Printf("[WARN] Failed to add %s: %v\n", line, err)
				} else {
					fmt.Printf("[OK] Added %s to blacklist\n", line)
				}
			}
		}
	}
	return scanner.Err()
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
func ImportWhitelistFromFile(s *sdk.SDK, path string) error {
	// 验证文件路径和大小
	// Validate file path and size
	safePath, err := ValidateImportFile(path)
	if err != nil {
		return err
	}

	// Whitelist usually doesn't have a separate persistence file in the same way,
	// or it relies on config.yaml syncing.
	// But AddWithFile is not available for WhitelistAPI.
	// So we just Add(), and user should run 'sync to-config' to persist if needed.

	file, err := os.Open(safePath)
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
			// 验证 IP 格式
			// Validate IP format
			if err := ValidateIP(ip); err != nil {
				fmt.Printf("[WARN] Invalid IP format: %s: %v\n", line, err)
				continue
			}
			var port uint16
			if len(parts) > 1 {
				p, pErr := strconv.Atoi(parts[1])
				if pErr != nil {
					fmt.Printf("[WARN] Invalid port in %s: %v\n", line, pErr)
					continue
				}
				// 验证端口范围：0-65535
				// Validate port range: 0-65535
				if !IsValidPort(p) {
					fmt.Printf("[WARN] Port out of range in %s: %d (must be 0-65535)\n", line, p)
					continue
				}
				port = uint16(p) // #nosec G115 // port is validated 0-65535
			}

			if err := s.Whitelist.Add(ip, port); err != nil {
				fmt.Printf("[WARN] Failed to add %s: %v\n", line, err)
			} else {
				fmt.Printf("[OK] Added %s to whitelist\n", line)
			}
		}
	}
	return scanner.Err()
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
func ImportIPPortRulesFromFile(s *sdk.SDK, path string) error {
	// 验证文件路径和大小
	// Validate file path and size
	safePath, err := ValidateImportFile(path)
	if err != nil {
		return err
	}

	file, err := os.Open(safePath)
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
				fmt.Printf("[WARN] Invalid format: %s (expected IP:Port:Action)\n", line)
				continue
			}
			ip := parts[0]
			// 验证 IP 格式
			// Validate IP format
			if err := ValidateIP(ip); err != nil {
				fmt.Printf("[WARN] Invalid IP format: %s: %v\n", line, err)
				continue
			}
			port, pErr := strconv.Atoi(parts[1])
			if pErr != nil {
				fmt.Printf("[WARN] Invalid port in %s: %v\n", line, pErr)
				continue
			}
			// 验证端口范围：0-65535
			// Validate port range: 0-65535
			if !IsValidPort(port) {
				fmt.Printf("[WARN] Port out of range in %s: %d (must be 0-65535)\n", line, port)
				continue
			}
			actionStr := strings.ToLower(parts[2])
			action := uint8(2) // Deny default
			if actionStr == "allow" {
				action = 1
			}

			if err := s.Rule.AddIPPortRule(ip, uint16(port), action); err != nil { // #nosec G115 // port is validated 0-65535
				fmt.Printf("[WARN] Failed to add rule %s: %v\n", line, err)
			} else {
				fmt.Printf("[OK] Added rule %s\n", line)
			}
		}
	}
	return scanner.Err()
}
