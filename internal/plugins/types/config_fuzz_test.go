package types

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzLoadGlobalConfig tests LoadGlobalConfig with random file content
// FuzzLoadGlobalConfig 使用随机文件内容测试 LoadGlobalConfig
func FuzzLoadGlobalConfig(f *testing.F) {
	// Seed corpus: various YAML content
	// 种子语料库：各种 YAML 内容
	seedCorpus := []string{
		// Valid config
		// 有效配置
		`
base:
  default_deny: true
  allow_return_traffic: true
  allow_icmp: true
  interfaces: []
  whitelist: [],
`,
		// Empty config
		// 空配置
		``,
		// Invalid YAML
		// 无效 YAML
		`invalid: yaml: content: [`,
		// Partial config
		// 部分配置
		`
base:
  default_deny: false
`,
		// Config with invalid types
		// 类型错误的配置
		`
base:
  default_deny: "not_a_bool"
  allow_return_traffic: 123
`,
		// Config with extra fields
		// 包含额外字段的配置
		`
base:
  default_deny: true
  unknown_field: "should be ignored"
extra_section:
  some_data: true
`,
		// Config with large whitelist
		// 包含大型白名单的配置
		`
base:
  whitelist:
    - "192.168.1.1/32"
    - "10.0.0.0/8"
    - "2001:db8::/32"
`,
		// Config with special characters
		// 包含特殊字符的配置
		`
base:
  bpf_pin_path: "/sys/fs/bpf/netxfw-test"
  lock_list_file: "/etc/netxfw/lock_list_test.txt"
`,
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		// Create temp file
		// 创建临时文件
		tmpDir := t.TempDir()
		tmpFile := tmpDir + "/config.yaml"

		// Write content to temp file
		// 将内容写入临时文件
		err := os.WriteFile(tmpFile, []byte(content), 0644)
		if err != nil {
			return
		}

		// LoadGlobalConfig should not panic on any input
		// LoadGlobalConfig 不应在任何输入上发生 panic
		cfg, err := LoadGlobalConfig(tmpFile)

		if err != nil {
			// If error, that's acceptable
			// 如果出错，这是可接受的
			return
		}

		// If no error, config should be non-nil
		// 如果没有错误，配置应为非 nil
		if cfg == nil {
			t.Errorf("LoadGlobalConfig returned nil without error")
			return
		}

		// Verify config can be saved and loaded again
		// 验证配置可以保存并再次加载
		tmpFile2 := tmpDir + "/config2.yaml"
		err = SaveGlobalConfig(tmpFile2, cfg)
		if err != nil {
			t.Errorf("SaveGlobalConfig failed: %v", err)
			return
		}

		cfg2, err := LoadGlobalConfig(tmpFile2)
		if err != nil {
			t.Errorf("LoadGlobalConfig after save failed: %v", err)
			return
		}

		if cfg2 == nil {
			t.Errorf("LoadGlobalConfig after save returned nil without error")
		}
	})
}

// FuzzParseBaseConfig tests parsing base config with random inputs
// FuzzParseBaseConfig 使用随机输入测试基础配置解析
func FuzzParseBaseConfig(f *testing.F) {
	seedCorpus := []string{
		`default_deny: true`,
		`default_deny: false`,
		`default_deny: "true"`,
		`default_deny: 1`,
		`allow_return_traffic: true`,
		`allow_icmp: true`,
		`interfaces: ["eth0", "eth1"]`,
		`whitelist: ["192.168.1.1/32"]`,
		`invalid_field: "test"`,
		``,
		`invalid yaml [`,
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		// Parse as BaseConfig
		// 解析为 BaseConfig
		var cfg BaseConfig
		err := yaml.Unmarshal([]byte(content), &cfg)

		if err != nil {
			// Parse error is acceptable
			// 解析错误是可接受的
			return
		}

		// If no error, verify the config
		// 如果没有错误，验证配置
		_ = cfg.DefaultDeny
		_ = cfg.AllowReturnTraffic
		_ = cfg.AllowICMP
		_ = cfg.Interfaces
		_ = cfg.Whitelist
	})
}

// FuzzValidateConfig tests config validation with random inputs
// FuzzValidateConfig 使用随机输入测试配置验证
func FuzzValidateConfig(f *testing.F) {
	seedCorpus := []struct {
		defaultDeny    bool
		allowReturn    bool
		allowICMP      bool
		enableAFXDP    bool
		strictTCP      bool
		synLimit       bool
		bogonFilter    bool
		strictProtocol bool
		dropFragments  bool
	}{
		{true, true, true, false, false, false, false, false, false},
		{false, false, false, false, false, false, false, false, false},
		{true, true, true, true, true, true, true, true, true},
	}

	for _, seed := range seedCorpus {
		f.Add(
			seed.defaultDeny,
			seed.allowReturn,
			seed.allowICMP,
			seed.enableAFXDP,
			seed.strictTCP,
			seed.synLimit,
			seed.bogonFilter,
			seed.strictProtocol,
			seed.dropFragments,
		)
	}

	f.Fuzz(func(t *testing.T,
		defaultDeny, allowReturn, allowICMP, enableAFXDP bool,
		strictTCP, synLimit, bogonFilter, strictProtocol bool,
		dropFragments bool,
	) {
		// Create config with random boolean values
		// 使用随机布尔值创建配置
		cfg := &GlobalConfig{
			Base: BaseConfig{
				DefaultDeny:        defaultDeny,
				AllowReturnTraffic: allowReturn,
				AllowICMP:          allowICMP,
				EnableAFXDP:        enableAFXDP,
				StrictTCP:          strictTCP,
				SYNLimit:           synLimit,
				BogonFilter:        bogonFilter,
				StrictProtocol:     strictProtocol,
				DropFragments:      dropFragments,
			},
		}

		// Validate should not panic
		// Validate 不应发生 panic
		_ = cfg.Validate()
	})
}

// FuzzWhitelistParsing tests whitelist parsing with random inputs
// FuzzWhitelistParsing 使用随机输入测试白名单解析
func FuzzWhitelistParsing(f *testing.F) {
	seedCorpus := []string{
		`whitelist: []`,
		`whitelist: ["192.168.1.1/32"]`,
		`whitelist: ["192.168.1.1/32", "10.0.0.0/8", "2001:db8::/32"]`,
		`whitelist: ["invalid"]`,
		`whitelist: [""]`,
		`whitelist: "not_an_array"`,
		`whitelist: [123, 456]`,
		``,
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		var cfg struct {
			Whitelist []string `yaml:"whitelist"`
		}

		err := yaml.Unmarshal([]byte(content), &cfg)
		if err != nil {
			return
		}

		// Verify whitelist entries
		// 验证白名单条目
		for _, entry := range cfg.Whitelist {
			// Each entry should be a string
			// 每个条目应为字符串
			_ = entry
		}
	})
}

// FuzzInterfacesParsing tests interfaces parsing with random inputs
// FuzzInterfacesParsing 使用随机输入测试接口解析
func FuzzInterfacesParsing(f *testing.F) {
	seedCorpus := []string{
		`interfaces: []`,
		`interfaces: ["eth0"]`,
		`interfaces: ["eth0", "eth1", "wlan0"]`,
		`interfaces: [""]`,
		`interfaces: "not_an_array"`,
		`interfaces: [123]`,
		``,
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		var cfg struct {
			Interfaces []string `yaml:"interfaces"`
		}

		err := yaml.Unmarshal([]byte(content), &cfg)
		if err != nil {
			return
		}

		// Verify interface entries
		// 验证接口条目
		for _, iface := range cfg.Interfaces {
			_ = iface
		}
	})
}

// FuzzCleanupIntervalParsing tests cleanup interval parsing with random inputs
// FuzzCleanupIntervalParsing 使用随机输入测试清理间隔解析
func FuzzCleanupIntervalParsing(f *testing.F) {
	seedCorpus := []string{
		`cleanup_interval: "1m"`,
		`cleanup_interval: "5m"`,
		`cleanup_interval: "1h"`,
		`cleanup_interval: "30s"`,
		`cleanup_interval: ""`,
		`cleanup_interval: "invalid"`,
		`cleanup_interval: 123`,
		`cleanup_interval: "1d"`,
		``,
	}

	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		var cfg struct {
			CleanupInterval string `yaml:"cleanup_interval"`
		}

		err := yaml.Unmarshal([]byte(content), &cfg)
		if err != nil {
			return
		}

		// Try to parse the interval
		// 尝试解析间隔
		_ = cfg.CleanupInterval
	})
}
