package unit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
)

func setupTestConfig(t *testing.T) (string, string) {
	// Create temp dir
	tmpDir, err := os.MkdirTemp("", "netxfw_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockListPath := filepath.Join(tmpDir, "lock_list.txt")

	// Create dummy config
	cfg := types.GlobalConfig{}
	cfg.Base.LockListFile = lockListPath
	cfg.Base.PersistRules = true
	cfg.Base.Whitelist = []string{}

	if err := types.SaveGlobalConfig(configPath, &cfg); err != nil {
		t.Fatalf("Failed to save temp config: %v", err)
	}

	// Set runtime config path
	runtime.ConfigPath = configPath

	return tmpDir, configPath
}

func TestSyncLockMap(t *testing.T) {
	tmpDir, _ := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }() // Reset

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Test 1: Lock an IP
	ip := "192.168.1.1"
	err := core.SyncLockMap(ctx, mgr, ip, true, true)
	if err != nil {
		t.Fatalf("SyncLockMap failed: %v", err)
	}
	if !mgr.Blacklist[ip+"/32"] {
		t.Errorf("IP %s should be in blacklist", ip)
	}

	// Test 2: Unlock an IP
	err = core.SyncLockMap(ctx, mgr, ip, false, true)
	if err != nil {
		t.Fatalf("SyncLockMap unlock failed: %v", err)
	}
	if mgr.Blacklist[ip+"/32"] {
		t.Errorf("IP %s should not be in blacklist", ip)
	}
}

func TestSyncWhitelistMap(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	ip := "10.0.0.1"
	port := uint16(80)

	// Test 1: Add to Whitelist
	core.SyncWhitelistMap(ctx, mgr, ip, port, true, true)
	if mgr.WhitelistMap[ip+"/32"] != port {
		t.Errorf("IP %s should be in whitelist with port %d", ip, port)
	}

	// Verify config update
	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}
	found := false
	for _, w := range cfg.Base.Whitelist {
		if strings.Contains(w, ip) || iputil.NormalizeCIDR(w) == iputil.NormalizeCIDR(ip) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IP %s should be in whitelist config", ip)
	}

	// Test 2: Remove from Whitelist
	core.SyncWhitelistMap(ctx, mgr, ip, port, false, true)
	if _, ok := mgr.WhitelistMap[ip+"/32"]; ok {
		t.Errorf("IP %s should not be in whitelist", ip)
	}
}

func TestConflictResolution_WhitelistToBlacklist(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Setup: Add IP to whitelist in config AND mock manager
	ip := "1.2.3.4"

	// Add to mock manager
	mgr.AddWhitelistIP(ip, 0)

	// Add to config file
	cfg, _ := types.LoadGlobalConfig(configPath)
	cfg.Base.Whitelist = append(cfg.Base.Whitelist, ip)
	types.SaveGlobalConfig(configPath, cfg)

	// Mock user input "y" to confirm removal from whitelist
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))

	// Execute Lock
	err := core.SyncLockMap(ctx, mgr, ip, true, false)
	if err != nil {
		t.Fatalf("SyncLockMap failed: %v", err)
	}

	// Verify: Should be in blacklist, not in whitelist
	if !mgr.Blacklist[ip+"/32"] {
		t.Errorf("IP %s should be in blacklist", ip)
	}
	if _, ok := mgr.WhitelistMap[ip+"/32"]; ok {
		t.Errorf("IP %s should NOT be in whitelist (manager)", ip)
	}

	// Verify config file update
	cfg, _ = types.LoadGlobalConfig(configPath)
	for _, w := range cfg.Base.Whitelist {
		if iputil.NormalizeCIDR(w) == iputil.NormalizeCIDR(ip) {
			t.Errorf("IP %s should be removed from whitelist config", ip)
		}
	}
}

func TestConflictResolution_BlacklistToWhitelist(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Setup: Add IP to blacklist
	ip := "5.6.7.8"
	mgr.AddBlacklistIP(ip)

	// Mock user input "y"
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))

	// Execute Whitelist
	_ = core.SyncWhitelistMap(ctx, mgr, ip, 0, true, false)

	// Verify
	if mgr.Blacklist[ip+"/32"] {
		t.Errorf("IP %s should NOT be in blacklist", ip)
	}
	if _, ok := mgr.WhitelistMap[ip+"/32"]; !ok {
		t.Errorf("IP %s should be in whitelist", ip)
	}

	// Verify config file update
	cfg, _ := types.LoadGlobalConfig(configPath)
	found := false
	for _, w := range cfg.Base.Whitelist {
		if iputil.NormalizeCIDR(w) == iputil.NormalizeCIDR(ip) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IP %s should be in whitelist config", ip)
	}
}

func TestVerifyAndRepair(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()

	// 1. Setup stale state in manager (not in config)
	// 在管理器中设置过时状态（不在配置中）
	staleIP := "9.9.9.9"
	mgr.AddBlacklistIP(staleIP)
	mgr.AddWhitelistIP("8.8.8.8", 53)

	// 2. Setup desired state in config
	// 在配置中设置期望状态
	cfg, _ := types.LoadGlobalConfig(configPath)
	validIP := "1.1.1.1"
	cfg.Base.Whitelist = []string{validIP}
	types.SaveGlobalConfig(configPath, cfg)

	// 3. Run VerifyAndRepair
	// 运行 VerifyAndRepair
	err := mgr.VerifyAndRepair(cfg)
	if err != nil {
		t.Fatalf("VerifyAndRepair failed: %v", err)
	}

	// 4. Verify results
	// 验证结果
	// Stale entries should be gone / 过时条目应该消失
	if mgr.Blacklist[staleIP+"/32"] {
		t.Errorf("Stale blacklist IP %s should have been removed", staleIP)
	}
	if _, ok := mgr.WhitelistMap["8.8.8.8/32"]; ok {
		t.Error("Stale whitelist IP 8.8.8.8 should have been removed")
	}

	// Config entries should be present / 配置条目应该存在
	if _, ok := mgr.WhitelistMap[validIP+"/32"]; !ok {
		t.Errorf("Valid whitelist IP %s should have been added", validIP)
	}
}

func TestConcurrentSyncLockMap(t *testing.T) {
	tmpDir, _ := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	var wg sync.WaitGroup
	numConcurrent := 20

	// Test concurrent additions
	// 测试并发添加
	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.2.%d", idx)
			_ = core.SyncLockMap(ctx, mgr, ip, true, true)
		}(i)
	}
	wg.Wait()

	if len(mgr.Blacklist) != numConcurrent {
		t.Errorf("Expected %d entries in blacklist, got %d", numConcurrent, len(mgr.Blacklist))
	}
}
