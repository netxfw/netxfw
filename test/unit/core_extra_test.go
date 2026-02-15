package unit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/livp123/netxfw/internal/core"
	"github.com/livp123/netxfw/internal/plugins/types"
	"github.com/livp123/netxfw/internal/runtime"
	"github.com/livp123/netxfw/internal/utils/iputil"
	"github.com/livp123/netxfw/internal/xdp"
)

func TestSyncIPPortRule(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	ip := "1.2.3.4"
	port := uint16(8080)
	action := uint8(1) // Allow

	// Test 1: Add rule
	err := core.SyncIPPortRule(ctx, mgr, ip, port, action, true)
	if err != nil {
		t.Fatalf("SyncIPPortRule add failed: %v", err)
	}

	key := ip + "/32"
	if mgr.IPPortRulesMap[key].Action != action {
		t.Errorf("Expected action %d for %s, got %d", action, key, mgr.IPPortRulesMap[key].Action)
	}

	// Verify config
	cfg, _ := types.LoadGlobalConfig(configPath)
	found := false
	targetCIDR := iputil.NormalizeCIDR(ip)
	for _, r := range cfg.Port.IPPortRules {
		if iputil.NormalizeCIDR(r.IP) == targetCIDR && r.Port == port && r.Action == action {
			found = true
			break
		}
	}
	if !found {
		t.Error("Rule not found in config")
	}

	// Test 2: Remove rule
	err = core.SyncIPPortRule(ctx, mgr, ip, port, action, false)
	if err != nil {
		t.Fatalf("SyncIPPortRule remove failed: %v", err)
	}
	if _, ok := mgr.IPPortRulesMap[key]; ok {
		t.Errorf("Rule %s should be removed from manager", key)
	}

	cfg, _ = types.LoadGlobalConfig(configPath)
	if len(cfg.Port.IPPortRules) != 0 {
		t.Error("Rule should be removed from config")
	}
}

func TestSyncRateLimitRule(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	ip := "192.168.1.100"
	rate := uint64(100)
	burst := uint64(200)

	// Test 1: Add rate limit
	err := core.SyncRateLimitRule(ctx, mgr, ip, rate, burst, true)
	if err != nil {
		t.Fatalf("SyncRateLimitRule add failed: %v", err)
	}

	if mgr.RateLimitRules[ip+"/32"].Rate != rate {
		t.Errorf("Expected rate %d, got %d", rate, mgr.RateLimitRules[ip+"/32"].Rate)
	}

	// Verify config
	cfg, _ := types.LoadGlobalConfig(configPath)
	if len(cfg.RateLimit.Rules) != 1 || cfg.RateLimit.Rules[0].IP != ip {
		t.Error("Rate limit rule not correctly saved in config")
	}

	// Test 2: Remove rate limit
	err = core.SyncRateLimitRule(ctx, mgr, ip, rate, burst, false)
	if err != nil {
		t.Fatalf("SyncRateLimitRule remove failed: %v", err)
	}
	if _, ok := mgr.RateLimitRules[ip+"/32"]; ok {
		t.Error("Rate limit rule should be removed from manager")
	}
}

func TestSyncDefaultDeny(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Test 1: Enable default deny
	err := core.SyncDefaultDeny(ctx, mgr, true)
	if err != nil {
		t.Fatalf("SyncDefaultDeny enable failed: %v", err)
	}
	if !mgr.DefaultDeny {
		t.Error("Default deny should be enabled in manager")
	}

	cfg, _ := types.LoadGlobalConfig(configPath)
	if !cfg.Base.DefaultDeny {
		t.Error("Default deny should be enabled in config")
	}

	// Test 2: Disable default deny
	err = core.SyncDefaultDeny(ctx, mgr, false)
	if err != nil {
		t.Fatalf("SyncDefaultDeny disable failed: %v", err)
	}
	if mgr.DefaultDeny {
		t.Error("Default deny should be disabled in manager")
	}
}

func TestClearBlacklist(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// 1. Setup: Add some IPs to blacklist
	core.SyncLockMap(ctx, mgr, "1.1.1.1", true, true)
	core.SyncLockMap(ctx, mgr, "2.2.2.2", true, true)

	cfg, _ := types.LoadGlobalConfig(configPath)
	lockFile := cfg.Base.LockListFile

	// 2. Clear
	err := core.ClearBlacklist(ctx, mgr)
	if err != nil {
		t.Fatalf("ClearBlacklist failed: %v", err)
	}

	// 3. Verify
	if len(mgr.Blacklist) != 0 {
		t.Errorf("Blacklist should be empty, got %d entries", len(mgr.Blacklist))
	}

	content, _ := os.ReadFile(lockFile)
	if len(strings.TrimSpace(string(content))) != 0 {
		t.Error("Persistence file should be empty")
	}
}

func TestSyncAutoBlock(t *testing.T) {
	tmpDir, configPath := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// Test 1: Enable AutoBlock
	err := core.SyncAutoBlock(ctx, mgr, true)
	if err != nil {
		t.Fatalf("SyncAutoBlock enable failed: %v", err)
	}
	cfg, _ := types.LoadGlobalConfig(configPath)
	if !cfg.RateLimit.AutoBlock {
		t.Error("AutoBlock should be enabled in config")
	}

	// Test 2: SyncAutoBlockExpiry
	err = core.SyncAutoBlockExpiry(ctx, mgr, 3600)
	if err != nil {
		t.Fatalf("SyncAutoBlockExpiry failed: %v", err)
	}
	cfg, _ = types.LoadGlobalConfig(configPath)
	if cfg.RateLimit.AutoBlockExpiry != "3600s" {
		t.Errorf("Expected expiry 3600s, got %s", cfg.RateLimit.AutoBlockExpiry)
	}
}

func TestImportFiles(t *testing.T) {
	tmpDir, _ := setupTestConfig(t)
	defer os.RemoveAll(tmpDir)
	defer func() { runtime.ConfigPath = "" }()

	mgr := xdp.NewMockManager()
	ctx := context.Background()

	// 1. Test ImportLockListFromFile
	lockFile := filepath.Join(tmpDir, "import_lock.txt")
	os.WriteFile(lockFile, []byte("1.1.1.1\n2.2.2.2\n# comment\n"), 0644)

	err := core.ImportLockListFromFile(ctx, mgr, lockFile)
	if err != nil {
		t.Fatalf("ImportLockListFromFile failed: %v", err)
	}
	if !mgr.Blacklist["1.1.1.1/32"] || !mgr.Blacklist["2.2.2.2/32"] {
		t.Error("Imported IPs missing from blacklist")
	}

	// 2. Test ImportIPPortRulesFromFile
	portFile := filepath.Join(tmpDir, "import_port.txt")
	os.WriteFile(portFile, []byte("3.3.3.3 80 allow\n4.4.4.4 443 deny\n"), 0644)

	err = core.ImportIPPortRulesFromFile(ctx, mgr, portFile)
	if err != nil {
		t.Fatalf("ImportIPPortRulesFromFile failed: %v", err)
	}
	if mgr.IPPortRulesMap["3.3.3.3/32"].Action != 1 || mgr.IPPortRulesMap["4.4.4.4/32"].Action != 2 {
		t.Error("Imported IP+Port rules missing or incorrect")
	}

	// 3. Test ImportWhitelistFromFile
	wlFile := filepath.Join(tmpDir, "import_wl.txt")
	os.WriteFile(wlFile, []byte("5.5.5.5\n6.6.6.6:80\n"), 0644)

	err = core.ImportWhitelistFromFile(ctx, mgr, wlFile)
	if err != nil {
		t.Fatalf("ImportWhitelistFromFile failed: %v", err)
	}
	if _, ok := mgr.WhitelistMap["5.5.5.5/32"]; !ok {
		t.Error("5.5.5.5 missing from whitelist")
	}
	// Note: WhitelistMap in MockManager might use normalized CIDR as key
	if mgr.WhitelistMap["6.6.6.6/32"] != 80 {
		t.Errorf("6.6.6.6 should have port 80, got %d", mgr.WhitelistMap["6.6.6.6/32"])
	}
}
