package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/netxfw/netxfw/internal/app"
	apprule "github.com/netxfw/netxfw/internal/app/rule"
	sdk "github.com/netxfw/netxfw/pkg/sdk"
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

	// In test mode, callers must explicitly inject a mock SDK.
	// 测试模式下必须显式注入 mock SDK，不能回退到缓存的真实 SDK。
	if app.IsTestMode() {
		return nil, fmt.Errorf("mock SDK not configured in test mode")
	}

	// Use double-checked locking for real SDK to avoid race condition
	// 使用双重检查锁定真实 SDK 以避免竞态条件
	realSDKMux.Lock()
	defer realSDKMux.Unlock()

	// Check again in case another goroutine created it while we waited for lock
	// 再次检查，以防其他 goroutine 在我们等待锁时创建了它
	if realSDK != nil {
		return realSDK, nil
	}

	realSDK, err := app.NewPinnedSDK()
	if err != nil {
		return nil, err
	}
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
	return apprule.ImportText(stdoutWriter{}, s, "lock", path)
}

// ImportWhitelistFromFile imports IPs from a file to the whitelist.
func ImportWhitelistFromFile(s *sdk.SDK, path string) error {
	return apprule.ImportText(stdoutWriter{}, s, "allow", path)
}

// ImportIPPortRulesFromFile imports IP+Port rules from a file.
func ImportIPPortRulesFromFile(s *sdk.SDK, path string) error {
	return apprule.ImportText(stdoutWriter{}, s, "rules", path)
}

type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return os.Stdout.WriteString(string(p))
}
