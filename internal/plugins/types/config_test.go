package types

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestLoadGlobalConfig_NonExistent tests loading from non-existent file
// TestLoadGlobalConfig_NonExistent 测试从不存在的文件加载
func TestLoadGlobalConfig_NonExistent(t *testing.T) {
	_, err := LoadGlobalConfig("/non/existent/path/config.yaml")
	assert.Error(t, err)
}

// TestLoadGlobalConfig_Valid tests loading a valid config file
// TestLoadGlobalConfig_Valid 测试加载有效配置文件
func TestLoadGlobalConfig_Valid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
base:
  default_deny: true
  whitelist:
    - 192.168.1.0/24
web:
  enabled: true
  port: 8080
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	cfg, err := LoadGlobalConfig(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.True(t, cfg.Base.DefaultDeny)
	assert.True(t, cfg.Web.Enabled)
	assert.Equal(t, 8080, cfg.Web.Port)
}

// TestLoadGlobalConfig_Empty tests loading an empty config file
// TestLoadGlobalConfig_Empty 测试加载空配置文件
func TestLoadGlobalConfig_Empty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(""), 0644)
	assert.NoError(t, err)

	cfg, err := LoadGlobalConfig(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	// Should have default values
	// 应该有默认值
	assert.True(t, cfg.Base.DefaultDeny)
}

// TestSaveGlobalConfig tests saving config to file
// TestSaveGlobalConfig 测试保存配置到文件
func TestSaveGlobalConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &GlobalConfig{
		Base: BaseConfig{
			DefaultDeny: true,
			Whitelist:   []string{"192.168.1.0/24"},
		},
		Web: WebConfig{
			Enabled: true,
			Port:    8080,
		},
	}

	err = SaveGlobalConfig(configPath, cfg)
	assert.NoError(t, err)

	// Verify file was created
	// 验证文件已创建
	_, err = os.Stat(configPath)
	assert.NoError(t, err)

	// Load and verify content
	// 加载并验证内容
	loadedCfg, err := LoadGlobalConfig(configPath)
	assert.NoError(t, err)
	assert.True(t, loadedCfg.Base.DefaultDeny)
	assert.Equal(t, 8080, loadedCfg.Web.Port)
}

// TestSaveGlobalConfig_UpdateExisting tests updating existing config file
// TestSaveGlobalConfig_UpdateExisting 测试更新现有配置文件
func TestSaveGlobalConfig_UpdateExisting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create initial config
	// 创建初始配置
	initialContent := `
base:
  default_deny: false
  whitelist:
    - 10.0.0.0/8
web:
  enabled: false
  port: 9090
`
	err = os.WriteFile(configPath, []byte(initialContent), 0644)
	assert.NoError(t, err)

	// Update config
	// 更新配置
	cfg := &GlobalConfig{
		Base: BaseConfig{
			DefaultDeny: true,
			Whitelist:   []string{"192.168.1.0/24"},
		},
		Web: WebConfig{
			Enabled: true,
			Port:    8080,
		},
	}

	err = SaveGlobalConfig(configPath, cfg)
	assert.NoError(t, err)

	// Verify updated content
	// 验证更新后的内容
	loadedCfg, err := LoadGlobalConfig(configPath)
	assert.NoError(t, err)
	assert.True(t, loadedCfg.Base.DefaultDeny)
	assert.Equal(t, 8080, loadedCfg.Web.Port)
}

// TestMergeYamlNodes tests the MergeYamlNodes function
// TestMergeYamlNodes 测试 MergeYamlNodes 函数
func TestMergeYamlNodes(t *testing.T) {
	targetYaml := `
base:
  default_deny: false
  whitelist:
    - 10.0.0.0/8
web:
  enabled: false
`
	sourceYaml := `
base:
  default_deny: true
web:
  enabled: true
  port: 8080
`

	var targetNode, sourceNode yaml.Node
	err := yaml.Unmarshal([]byte(targetYaml), &targetNode)
	assert.NoError(t, err)
	err = yaml.Unmarshal([]byte(sourceYaml), &sourceNode)
	assert.NoError(t, err)

	MergeYamlNodes(&targetNode, &sourceNode)

	// Verify merge happened
	// 验证合并已发生
	var result map[string]interface{}
	err = yaml.Unmarshal([]byte(targetYaml), &result)
	assert.NoError(t, err)
}

// TestGlobalConfig_Defaults tests default values
// TestGlobalConfig_Defaults 测试默认值
func TestGlobalConfig_Defaults(t *testing.T) {
	// Test that defaults are applied when loading
	// 测试加载时应用默认值
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	err = os.WriteFile(configPath, []byte("{}"), 0644)
	assert.NoError(t, err)

	loadedCfg, err := LoadGlobalConfig(configPath)
	assert.NoError(t, err)

	// Verify defaults
	// 验证默认值
	assert.True(t, loadedCfg.Base.DefaultDeny)
	assert.True(t, loadedCfg.Base.AllowICMP)
	assert.True(t, loadedCfg.Conntrack.Enabled)
	assert.True(t, loadedCfg.RateLimit.Enabled)
	assert.Equal(t, 11811, loadedCfg.Web.Port)
	assert.Equal(t, 11812, loadedCfg.Metrics.Port)
}

// TestBaseConfig_Fields tests BaseConfig field assignments
// TestBaseConfig_Fields 测试 BaseConfig 字段赋值
func TestBaseConfig_Fields(t *testing.T) {
	cfg := BaseConfig{
		DefaultDeny:        true,
		AllowReturnTraffic: true,
		AllowICMP:          false,
		PersistRules:       true,
		CleanupInterval:    "5m",
		ICMPRate:           20,
		ICMPBurst:          100,
		LockListV4Mask:     24,
		LockListV6Mask:     64,
		EnablePprof:        true,
		PprofPort:          6060,
		Whitelist:          []string{"192.168.1.0/24"},
	}

	assert.True(t, cfg.DefaultDeny)
	assert.True(t, cfg.AllowReturnTraffic)
	assert.False(t, cfg.AllowICMP)
	assert.Equal(t, "5m", cfg.CleanupInterval)
	assert.Equal(t, 24, cfg.LockListV4Mask)
}

// TestWebConfig_Fields tests WebConfig field assignments
// TestWebConfig_Fields 测试 WebConfig 字段赋值
func TestWebConfig_Fields(t *testing.T) {
	cfg := WebConfig{
		Enabled: true,
		Port:    8080,
		Token:   "test-token",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "test-token", cfg.Token)
}

// TestMetricsConfig_Fields tests MetricsConfig field assignments
// TestMetricsConfig_Fields 测试 MetricsConfig 字段赋值
func TestMetricsConfig_Fields(t *testing.T) {
	cfg := MetricsConfig{
		Enabled:       true,
		ServerEnabled: true,
		Port:          9090,
	}

	assert.True(t, cfg.Enabled)
	assert.True(t, cfg.ServerEnabled)
	assert.Equal(t, 9090, cfg.Port)
}

// TestConntrackConfig_Fields tests ConntrackConfig field assignments
// TestConntrackConfig_Fields 测试 ConntrackConfig 字段赋值
func TestConntrackConfig_Fields(t *testing.T) {
	cfg := ConntrackConfig{
		Enabled:    true,
		MaxEntries: 50000,
		TCPTimeout: "2h",
		UDPTimeout: "10m",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 50000, cfg.MaxEntries)
	assert.Equal(t, "2h", cfg.TCPTimeout)
}

// TestRateLimitConfig_Fields tests RateLimitConfig field assignments
// TestRateLimitConfig_Fields 测试 RateLimitConfig 字段赋值
func TestRateLimitConfig_Fields(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:         true,
		AutoBlock:       true,
		AutoBlockExpiry: "30m",
		Rules: []RateLimitRule{
			{IP: "192.168.1.0/24", Rate: 1000, Burst: 2000},
		},
	}

	assert.True(t, cfg.Enabled)
	assert.True(t, cfg.AutoBlock)
	assert.Len(t, cfg.Rules, 1)
}

// TestCapacityConfig_Fields tests CapacityConfig field assignments
// TestCapacityConfig_Fields 测试 CapacityConfig 字段赋值
func TestCapacityConfig_Fields(t *testing.T) {
	cfg := CapacityConfig{
		Conntrack:    200000,
		LockList:     1000000,
		Whitelist:    131072,
		IPPortRules:  131072,
		AllowedPorts: 2048,
	}

	assert.Equal(t, 200000, cfg.Conntrack)
	assert.Equal(t, 1000000, cfg.LockList)
}

// TestLoggingConfig_Fields tests LoggingConfig field assignments
// TestLoggingConfig_Fields 测试 LoggingConfig 字段赋值
func TestLoggingConfig_Fields(t *testing.T) {
	cfg := LoggingConfig{
		Enabled:    true,
		Path:       "/var/log/test.log",
		MaxSize:    20,
		MaxBackups: 5,
		MaxAge:     60,
		Compress:   false,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "/var/log/test.log", cfg.Path)
	assert.Equal(t, 20, cfg.MaxSize)
}

// TestPortConfig_Fields tests PortConfig field assignments
// TestPortConfig_Fields 测试 PortConfig 字段赋值
func TestPortConfig_Fields(t *testing.T) {
	cfg := PortConfig{
		IPPortRules: []IPPortRule{
			{IP: "192.168.1.1", Port: 80, Action: 1},
			{IP: "10.0.0.1", Port: 443, Action: 2},
		},
	}

	assert.Len(t, cfg.IPPortRules, 2)
	assert.Equal(t, "192.168.1.1", cfg.IPPortRules[0].IP)
	assert.Equal(t, uint16(80), cfg.IPPortRules[0].Port)
}

// TestLogEngineConfig_Fields tests LogEngineConfig field assignments
// TestLogEngineConfig_Fields 测试 LogEngineConfig 字段赋值
func TestLogEngineConfig_Fields(t *testing.T) {
	cfg := LogEngineConfig{
		Enabled: true,
		Workers: 8,
		Rules: []LogEngineRule{
			{Path: "/var/log/auth.log", Action: "block"},
		},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 8, cfg.Workers)
	assert.Len(t, cfg.Rules, 1)
}

// TestAIConfig_Fields tests AIConfig field assignments
// TestAIConfig_Fields 测试 AIConfig 字段赋值
func TestAIConfig_Fields(t *testing.T) {
	cfg := AIConfig{
		Enabled: true,
		Port:    11813,
		APIKey:  "test-key",
		Model:   "gpt-4",
		BaseURL: "https://api.openai.com",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 11813, cfg.Port)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, "gpt-4", cfg.Model)
}

// TestMCPConfig_Fields tests MCPConfig field assignments
// TestMCPConfig_Fields 测试 MCPConfig 字段赋值
func TestMCPConfig_Fields(t *testing.T) {
	cfg := MCPConfig{
		Enabled: true,
		Port:    11814,
		Mode:    "sse",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 11814, cfg.Port)
	assert.Equal(t, "sse", cfg.Mode)
}

// TestClusterConfig_Fields tests ClusterConfig field assignments
// TestClusterConfig_Fields 测试 ClusterConfig 字段赋值
func TestClusterConfig_Fields(t *testing.T) {
	cfg := ClusterConfig{
		Enabled:    true,
		ConfigPath: "cluster.yaml",
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "cluster.yaml", cfg.ConfigPath)
}

// TestCleanDeprecatedClusterFields tests removing deprecated cluster fields
// TestCleanDeprecatedClusterFields 测试移除已弃用的集群字段
func TestCleanDeprecatedClusterFields(t *testing.T) {
	// Config with deprecated fields
	// 包含已弃用字段的配置
	configWithDeprecated := `
cluster:
  enabled: false
  configpath: cluster.yaml
  port: 11815
  nodes:
    - "node1:11815"
    - "node2:11815"
  secret: "my-secret"
base:
  default_deny: true
`

	var node yaml.Node
	err := yaml.Unmarshal([]byte(configWithDeprecated), &node)
	assert.NoError(t, err)

	// Clean deprecated fields
	// 清理已弃用字段
	CleanDeprecatedClusterFields(&node)

	// Marshal back to string
	// 序列化回字符串
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	err = enc.Encode(&node)
	assert.NoError(t, err)

	result := buf.String()

	// Verify deprecated fields are removed
	// 验证已弃用字段已移除
	assert.Contains(t, result, "enabled: false")
	assert.Contains(t, result, "configpath: cluster.yaml")
	assert.NotContains(t, result, "port: 11815")
	assert.NotContains(t, result, "nodes:")
	assert.NotContains(t, result, "secret:")

	// Verify other fields are preserved
	// 验证其他字段保留
	assert.Contains(t, result, "base:")
	assert.Contains(t, result, "default_deny: true")
}

// TestSaveGlobalConfig_CleansDeprecatedFields tests that SaveGlobalConfig cleans deprecated fields
// TestSaveGlobalConfig_CleansDeprecatedFields 测试 SaveGlobalConfig 清理已弃用字段
func TestSaveGlobalConfig_CleansDeprecatedFields(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create config with deprecated cluster fields
	// 创建包含已弃用集群字段的配置
	initialContent := `
cluster:
  enabled: false
  configpath: cluster.yaml
  port: 11815
  nodes:
    - "node1:11815"
  secret: "old-secret"
base:
  default_deny: false
`
	err = os.WriteFile(configPath, []byte(initialContent), 0644)
	assert.NoError(t, err)

	// Save config (should clean deprecated fields)
	// 保存配置（应清理已弃用字段）
	cfg := &GlobalConfig{
		Cluster: ClusterConfig{
			Enabled:    false,
			ConfigPath: "cluster.yaml",
		},
		Base: BaseConfig{
			DefaultDeny: true,
		},
	}

	err = SaveGlobalConfig(configPath, cfg)
	assert.NoError(t, err)

	// Read file and verify deprecated fields are removed
	// 读取文件并验证已弃用字段已移除
	content, err := os.ReadFile(configPath)
	assert.NoError(t, err)
	contentStr := string(content)

	assert.Contains(t, contentStr, "enabled: false")
	assert.Contains(t, contentStr, "configpath: cluster.yaml")
	assert.NotContains(t, contentStr, "port: 11815")
	assert.NotContains(t, contentStr, "nodes:")
	assert.NotContains(t, contentStr, "secret:")
}
