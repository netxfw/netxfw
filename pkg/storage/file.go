package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// TOMLStore implements the Store interface using local TOML files.
// TOMLStore 使用本地 TOML 文件实现 Store 接口。
type TOMLStore struct {
	mu            sync.RWMutex
	configPath    string // path to main config (for whitelist) / 主配置路径（用于白名单）
	lockFilePath  string // path to lock list file / 锁定列表文件路径
	portRulesPath string // path for ip+port rules (could be same as config) / IP+端口规则路径（可以与配置相同）
}

// NewTOMLStore creates a new TOML-based storage provider.
// NewTOMLStore 创建一个新的基于 TOML 的存储提供程序。
func NewTOMLStore(configPath, lockFilePath string) *TOMLStore {
	return &TOMLStore{
		configPath:    configPath,
		lockFilePath:  lockFilePath,
		portRulesPath: configPath, // For now, store port rules in main config / 目前，将端口规则存储在主配置中
	}
}

// fileData internal structure for TOML serialization.
// fileData 用于 TOML 序列化的内部结构。
type fileData struct {
	Whitelist   []IPRule     `toml:"whitelist"`
	LockList    []IPRule     `toml:"lock_list"`
	IPPortRules []IPPortRule `toml:"ip_port_rules"`
}

// AddIP adds an IP/CIDR to the specified list in the TOML file.
// AddIP 将 IP/CIDR 添加到 TOML 文件中的指定列表。
func (s *TOMLStore) AddIP(ruleType RuleType, cidr string, expiresAt *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cidr = NormalizeCIDR(cidr)
	rule := IPRule{CIDR: cidr, ExpiresAt: expiresAt}

	if ruleType == RuleTypeLockList {
		return s.updateFile(s.lockFilePath, func(data *fileData) {
			for i, existing := range data.LockList {
				if existing.CIDR == cidr {
					data.LockList[i] = rule
					return
				}
			}
			data.LockList = append(data.LockList, rule)
		})
	} else if ruleType == RuleTypeWhitelist {
		return s.updateFile(s.configPath, func(data *fileData) {
			for i, existing := range data.Whitelist {
				if existing.CIDR == cidr {
					data.Whitelist[i] = rule
					return
				}
			}
			data.Whitelist = append(data.Whitelist, rule)
		})
	}
	return fmt.Errorf("unsupported rule type: %s", ruleType)
}

// RemoveIP removes an IP/CIDR from the specified list in the TOML file.
// RemoveIP 从 TOML 文件中的指定列表中移除 IP/CIDR。
func (s *TOMLStore) RemoveIP(ruleType RuleType, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cidr = NormalizeCIDR(cidr)

	if ruleType == RuleTypeLockList {
		return s.updateFile(s.lockFilePath, func(data *fileData) {
			newList := []IPRule{}
			for _, existing := range data.LockList {
				if existing.CIDR != cidr {
					newList = append(newList, existing)
				}
			}
			data.LockList = newList
		})
	} else if ruleType == RuleTypeWhitelist {
		return s.updateFile(s.configPath, func(data *fileData) {
			newList := []IPRule{}
			for _, existing := range data.Whitelist {
				if existing.CIDR != cidr {
					newList = append(newList, existing)
				}
			}
			data.Whitelist = newList
		})
	}
	return fmt.Errorf("unsupported rule type: %s", ruleType)
}

// AddIPPortRule adds an IP+Port rule to the TOML file.
// AddIPPortRule 将 IP+端口规则添加到 TOML 文件中。
func (s *TOMLStore) AddIPPortRule(rule IPPortRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rule.CIDR = NormalizeCIDR(rule.CIDR)

	return s.updateFile(s.portRulesPath, func(data *fileData) {
		for i, existing := range data.IPPortRules {
			if existing.CIDR == rule.CIDR && existing.Port == rule.Port && existing.Protocol == rule.Protocol {
				data.IPPortRules[i] = rule
				return
			}
		}
		data.IPPortRules = append(data.IPPortRules, rule)
	})
}

// RemoveIPPortRule removes an IP+Port rule from the TOML file.
// RemoveIPPortRule 从 TOML 文件中移除 IP+端口规则。
func (s *TOMLStore) RemoveIPPortRule(cidr string, port uint16, protocol string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cidr = NormalizeCIDR(cidr)

	return s.updateFile(s.portRulesPath, func(data *fileData) {
		newList := []IPPortRule{}
		for _, existing := range data.IPPortRules {
			if !(existing.CIDR == cidr && existing.Port == port && existing.Protocol == protocol) {
				newList = append(newList, existing)
			}
		}
		data.IPPortRules = newList
	})
}

// LoadAll reads all rules from the TOML files.
// LoadAll 从 TOML 文件中读取所有规则。
func (s *TOMLStore) LoadAll() (whitelist []IPRule, lockList []IPRule, ipPortRules []IPPortRule, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Load from config / 从配置加载
	configData, cfgErr := s.readFile(s.configPath)
	if cfgErr == nil {
		whitelist = configData.Whitelist
		ipPortRules = configData.IPPortRules
	}

	// Load from lock file / 从锁定文件加载
	lockData, lockErr := s.readFile(s.lockFilePath)
	if lockErr == nil {
		lockList = lockData.LockList
	}

	return
}

func (s *TOMLStore) readRawFile(path string) (map[string]any, error) {
	data := make(map[string]any)
	safePath := filepath.Clean(path)      // Sanitize path to prevent directory traversal
	content, err := os.ReadFile(safePath) // #nosec G304 // path is sanitized with filepath.Clean
	if err != nil {
		return data, err
	}
	_, err = toml.Decode(string(content), &data)
	return data, err
}

func (s *TOMLStore) readFile(path string) (fileData, error) {
	var data fileData
	safePath := filepath.Clean(path)      // Sanitize path to prevent directory traversal
	content, err := os.ReadFile(safePath) // #nosec G304 // path is sanitized with filepath.Clean
	if err != nil {
		return data, err
	}
	_, err = toml.Decode(string(content), &data)
	return data, err
}

func (s *TOMLStore) updateFile(path string, updater func(*fileData)) error {
	// Read raw to preserve other fields / 读取原始数据以保留其他字段
	raw, rawErr := s.readRawFile(path)
	if rawErr != nil {
		raw = make(map[string]any)
	}

	// Read typed to easily modify / 读取类型化数据以便于修改
	typed, typedErr := s.readFile(path)
	if typedErr != nil {
		// Initialize empty fileData if file doesn't exist
		// 如果文件不存在，初始化空的 fileData
		typed = fileData{}
	}
	updater(&typed)

	// Sync typed back to raw / 将类型化数据同步回原始数据
	raw["whitelist"] = typed.Whitelist
	raw["lock_list"] = typed.LockList
	raw["ip_port_rules"] = typed.IPPortRules

	content, err := toml.Marshal(&raw)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0600)
}

// YAMLStore is an alias for TOMLStore for backward compatibility.
// YAMLStore 是 TOMLStore 的别名，用于向后兼容。
type YAMLStore = TOMLStore

// NewYAMLStore creates a new TOML-based storage provider (backward compatibility).
// NewYAMLStore 创建一个新的基于 TOML 的存储提供程序（向后兼容）。
func NewYAMLStore(configPath, lockFilePath string) *YAMLStore {
	return NewTOMLStore(configPath, lockFilePath)
}
