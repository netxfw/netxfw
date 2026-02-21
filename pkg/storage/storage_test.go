package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRuleType tests rule type constants
// TestRuleType 测试规则类型常量
func TestRuleType(t *testing.T) {
	assert.Equal(t, RuleType("whitelist"), RuleTypeWhitelist)
	assert.Equal(t, RuleType("lock_list"), RuleTypeLockList)
	assert.Equal(t, RuleType("ip_port"), RuleTypeIPPort)
}

// TestIPRule tests IPRule struct
// TestIPRule 测试 IPRule 结构体
func TestIPRule(t *testing.T) {
	// Test without expiration
	// 测试无过期时间
	rule := IPRule{
		CIDR: "192.168.1.0/24",
	}
	assert.Equal(t, "192.168.1.0/24", rule.CIDR)
	assert.Nil(t, rule.ExpiresAt)

	// Test with expiration
	// 测试有过期时间
	expiry := time.Now().Add(24 * time.Hour)
	ruleWithExpiry := IPRule{
		ExpiresAt: &expiry,
	}
	assert.NotNil(t, ruleWithExpiry.ExpiresAt)
}

// TestIPPortRule tests IPPortRule struct
// TestIPPortRule 测试 IPPortRule 结构体
func TestIPPortRule(t *testing.T) {
	rule := IPPortRule{
		CIDR:     "192.168.1.0/24",
		Port:     8080,
		Protocol: "tcp",
		Action:   "allow",
	}

	assert.Equal(t, "192.168.1.0/24", rule.CIDR)
	assert.Equal(t, uint16(8080), rule.Port)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, "allow", rule.Action)
}

// TestNormalizeCIDR tests the CIDR normalization helper
// TestNormalizeCIDR 测试 CIDR 标准化辅助函数
func TestNormalizeCIDR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"IPv4 Single", "192.168.1.1", "192.168.1.1/32"},
		{"IPv4 CIDR", "192.168.1.0/24", "192.168.1.0/24"},
		{"IPv6 Single", "2001:db8::1", "2001:db8::1/128"},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCIDR(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestYAMLStore_Creation tests YAMLStore creation
// TestYAMLStore_Creation 测试 YAMLStore 创建
func TestYAMLStore_Creation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	store := NewYAMLStore(configPath, lockPath)
	assert.NotNil(t, store)
}

// TestYAMLStore_AddIP tests adding IP rules
// TestYAMLStore_AddIP 测试添加 IP 规则
func TestYAMLStore_AddIP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create initial files
	// 创建初始文件
	os.WriteFile(configPath, []byte("whitelist: []\nlock_list: []\nip_port_rules: []\n"), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	// Test AddIP for whitelist
	// 测试白名单 AddIP
	err = store.AddIP(RuleTypeWhitelist, "192.168.1.1", nil)
	assert.NoError(t, err)

	// Test AddIP for lock list
	// 测试锁定列表 AddIP
	err = store.AddIP(RuleTypeLockList, "10.0.0.1", nil)
	assert.NoError(t, err)

	// Test AddIP with expiration
	// 测试带过期时间的 AddIP
	expiry := time.Now().Add(24 * time.Hour)
	err = store.AddIP(RuleTypeWhitelist, "192.168.1.2", &expiry)
	assert.NoError(t, err)
}

// TestYAMLStore_RemoveIP tests removing IP rules
// TestYAMLStore_RemoveIP 测试移除 IP 规则
func TestYAMLStore_RemoveIP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create initial files with some rules
	// 创建带有一些规则的初始文件
	os.WriteFile(configPath, []byte("whitelist:\n  - cidr: 192.168.1.1/32\nlock_list: []\nip_port_rules: []\n"), 0644)
	os.WriteFile(lockPath, []byte("lock_list:\n  - cidr: 10.0.0.1/32\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	// Test RemoveIP for whitelist
	// 测试白名单 RemoveIP
	err = store.RemoveIP(RuleTypeWhitelist, "192.168.1.1/32")
	assert.NoError(t, err)

	// Test RemoveIP for lock list
	// 测试锁定列表 RemoveIP
	err = store.RemoveIP(RuleTypeLockList, "10.0.0.1/32")
	assert.NoError(t, err)
}

// TestYAMLStore_AddIPPortRule tests adding IP port rules
// TestYAMLStore_AddIPPortRule 测试添加 IP 端口规则
func TestYAMLStore_AddIPPortRule(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create initial files
	// 创建初始文件
	os.WriteFile(configPath, []byte("whitelist: []\nlock_list: []\nip_port_rules: []\n"), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	rule := IPPortRule{
		CIDR:     "192.168.1.1",
		Port:     80,
		Protocol: "tcp",
		Action:   "allow",
	}

	err = store.AddIPPortRule(rule)
	assert.NoError(t, err)
}

// TestYAMLStore_RemoveIPPortRule tests removing IP port rules
// TestYAMLStore_RemoveIPPortRule 测试移除 IP 端口规则
func TestYAMLStore_RemoveIPPortRule(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create initial files with IP port rules
	// 创建带有 IP 端口规则的初始文件
	os.WriteFile(configPath, []byte(`whitelist: []
lock_list: []
ip_port_rules:
  - cidr: 192.168.1.1/32
    port: 80
    protocol: tcp
    action: allow
`), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	err = store.RemoveIPPortRule("192.168.1.1/32", 80, "tcp")
	assert.NoError(t, err)
}

// TestYAMLStore_LoadAll tests loading all rules
// TestYAMLStore_LoadAll 测试加载所有规则
func TestYAMLStore_LoadAll(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create initial files with rules
	// 创建带有规则的初始文件
	os.WriteFile(configPath, []byte(`whitelist:
  - cidr: 192.168.1.1/32
lock_list: []
ip_port_rules:
  - cidr: 10.0.0.1/32
    port: 443
    protocol: tcp
    action: deny
`), 0644)
	os.WriteFile(lockPath, []byte(`lock_list:
  - cidr: 172.16.0.1/32
`), 0644)

	store := NewYAMLStore(configPath, lockPath)

	whitelist, lockList, ipPortRules, err := store.LoadAll()
	assert.NoError(t, err)
	assert.Len(t, whitelist, 1)
	assert.Len(t, lockList, 1)
	assert.Len(t, ipPortRules, 1)

	assert.Equal(t, "192.168.1.1/32", whitelist[0].CIDR)
	assert.Equal(t, "172.16.0.1/32", lockList[0].CIDR)
	assert.Equal(t, "10.0.0.1/32", ipPortRules[0].CIDR)
	assert.Equal(t, uint16(443), ipPortRules[0].Port)
}

// TestYAMLStore_LoadAll_Empty tests loading from empty files
// TestYAMLStore_LoadAll_Empty 测试从空文件加载
func TestYAMLStore_LoadAll_Empty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	// Create empty files
	// 创建空文件
	os.WriteFile(configPath, []byte("whitelist: []\nlock_list: []\nip_port_rules: []\n"), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	whitelist, lockList, ipPortRules, err := store.LoadAll()
	assert.NoError(t, err)
	assert.Empty(t, whitelist)
	assert.Empty(t, lockList)
	assert.Empty(t, ipPortRules)
}

// TestYAMLStore_LoadAll_NonExistent tests loading from non-existent files
// TestYAMLStore_LoadAll_NonExistent 测试从不存在的文件加载
func TestYAMLStore_LoadAll_NonExistent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "nonexistent_config.yaml")
	lockPath := filepath.Join(tmpDir, "nonexistent_locklist.txt")

	store := NewYAMLStore(configPath, lockPath)

	whitelist, lockList, ipPortRules, err := store.LoadAll()
	// Should return empty lists without error
	// 应该返回空列表且无错误
	assert.NoError(t, err)
	assert.Empty(t, whitelist)
	assert.Empty(t, lockList)
	assert.Empty(t, ipPortRules)
}

// TestYAMLStore_AddIP_InvalidType tests adding IP with invalid type
// TestYAMLStore_AddIP_InvalidType 测试使用无效类型添加 IP
func TestYAMLStore_AddIP_InvalidType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	store := NewYAMLStore(configPath, lockPath)

	err = store.AddIP(RuleType("invalid"), "192.168.1.1", nil)
	assert.Error(t, err)
}

// TestYAMLStore_RemoveIP_InvalidType tests removing IP with invalid type
// TestYAMLStore_RemoveIP_InvalidType 测试使用无效类型移除 IP
func TestYAMLStore_RemoveIP_InvalidType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	store := NewYAMLStore(configPath, lockPath)

	err = store.RemoveIP(RuleType("invalid"), "192.168.1.1")
	assert.Error(t, err)
}

// TestYAMLStore_UpdateExistingRule tests updating an existing rule
// TestYAMLStore_UpdateExistingRule 测试更新现有规则
func TestYAMLStore_UpdateExistingRule(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	os.WriteFile(configPath, []byte("whitelist:\n  - cidr: 192.168.1.1/32\nlock_list: []\nip_port_rules: []\n"), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	// Add same IP again (should update)
	// 再次添加相同 IP（应该更新）
	expiry := time.Now().Add(24 * time.Hour)
	err = store.AddIP(RuleTypeWhitelist, "192.168.1.1", &expiry)
	assert.NoError(t, err)

	// Verify only one entry exists
	// 验证只有一个条目
	whitelist, _, _, err := store.LoadAll()
	assert.NoError(t, err)
	assert.Len(t, whitelist, 1)
	assert.NotNil(t, whitelist[0].ExpiresAt)
}

// TestYAMLStore_UpdateExistingIPPortRule tests updating an existing IP port rule
// TestYAMLStore_UpdateExistingIPPortRule 测试更新现有 IP 端口规则
func TestYAMLStore_UpdateExistingIPPortRule(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	lockPath := filepath.Join(tmpDir, "locklist.txt")

	os.WriteFile(configPath, []byte(`whitelist: []
lock_list: []
ip_port_rules:
  - cidr: 192.168.1.1/32
    port: 80
    protocol: tcp
    action: allow
`), 0644)
	os.WriteFile(lockPath, []byte("lock_list: []\n"), 0644)

	store := NewYAMLStore(configPath, lockPath)

	// Update the same rule
	// 更新相同规则
	rule := IPPortRule{
		CIDR:     "192.168.1.1",
		Port:     80,
		Protocol: "tcp",
		Action:   "deny", // Changed from allow to deny
	}

	err = store.AddIPPortRule(rule)
	assert.NoError(t, err)

	// Verify only one entry exists with new action
	// 验证只有一个条目且动作为新值
	_, _, ipPortRules, err := store.LoadAll()
	assert.NoError(t, err)
	assert.Len(t, ipPortRules, 1)
	assert.Equal(t, "deny", ipPortRules[0].Action)
}
