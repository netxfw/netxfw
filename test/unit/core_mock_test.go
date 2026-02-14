package unit

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
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
	err := core.SyncLockMap(ctx, mgr, ip, true)
	if err != nil {
		t.Fatalf("SyncLockMap failed: %v", err)
	}
	if !mgr.Blacklist[ip] {
		t.Errorf("IP %s should be in blacklist", ip)
	}

	// Test 2: Unlock an IP
	err = core.SyncLockMap(ctx, mgr, ip, false)
	if err != nil {
		t.Fatalf("SyncLockMap unlock failed: %v", err)
	}
	if mgr.Blacklist[ip] {
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

	// Test 1: Whitelist an IP
	core.SyncWhitelistMap(ctx, mgr, ip, port, true)
	if mgr.WhitelistMap[ip] != port {
		t.Errorf("IP %s should be in whitelist with port %d", ip, port)
	}

	// Verify config update
	cfg, err := types.LoadGlobalConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}
	found := false
	for _, w := range cfg.Base.Whitelist {
		if strings.Contains(w, ip) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IP %s should be in whitelist config", ip)
	}

	// Test 2: Remove from Whitelist
	core.SyncWhitelistMap(ctx, mgr, ip, port, false)
	if _, ok := mgr.WhitelistMap[ip]; ok {
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
	mgr.WhitelistMap[ip] = 0

	// Add to config file
	cfg, _ := types.LoadGlobalConfig(configPath)
	cfg.Base.Whitelist = append(cfg.Base.Whitelist, ip)
	types.SaveGlobalConfig(configPath, cfg)

	// Mock user input "y" to confirm removal from whitelist
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))

	// Execute Lock
	err := core.SyncLockMap(ctx, mgr, ip, true)
	if err != nil {
		t.Fatalf("SyncLockMap failed: %v", err)
	}

	// Verify: Should be in blacklist, not in whitelist
	if !mgr.Blacklist[ip] {
		t.Errorf("IP %s should be in blacklist", ip)
	}
	if _, ok := mgr.WhitelistMap[ip]; ok {
		t.Errorf("IP %s should NOT be in whitelist (manager)", ip)
	}

	// Verify config file update
	cfg, _ = types.LoadGlobalConfig(configPath)
	for _, w := range cfg.Base.Whitelist {
		if w == ip {
			t.Errorf("IP %s should be removed from whitelist config", ip)
		}
	}
}

func TestConflictResolution_BlacklistToWhitelist(t *testing.T) {
	tmpDir, _ := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Setup: Add IP to blacklist
	ip := "5.6.7.8"
	mgr.Blacklist[ip] = true

	// Mock user input "y"
	core.SetConfirmationReader(bufio.NewReader(strings.NewReader("y\n")))

	// Execute Whitelist
	core.SyncWhitelistMap(ctx, mgr, ip, 0, true)

	// Verify
	if mgr.Blacklist[ip] {
		t.Errorf("IP %s should NOT be in blacklist", ip)
	}
	if _, ok := mgr.WhitelistMap[ip]; !ok {
		t.Errorf("IP %s should be in whitelist", ip)
	}
}
