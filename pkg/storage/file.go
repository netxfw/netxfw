package storage

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// YAMLStore implements the Store interface using local YAML files
type YAMLStore struct {
	mu            sync.RWMutex
	configPath    string // path to main config (for whitelist)
	lockFilePath  string // path to lock list file
	portRulesPath string // path for ip+port rules (could be same as config)
}

func NewYAMLStore(configPath, lockFilePath string) *YAMLStore {
	return &YAMLStore{
		configPath:    configPath,
		lockFilePath:  lockFilePath,
		portRulesPath: configPath, // For now, store port rules in main config
	}
}

type fileData struct {
	Whitelist   []IPRule     `yaml:"whitelist"`
	LockList    []IPRule     `yaml:"lock_list"`
	IPPortRules []IPPortRule `yaml:"ip_port_rules"`
}

func (s *YAMLStore) AddIP(ruleType RuleType, cidr string, expiresAt *time.Time) error {
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

func (s *YAMLStore) RemoveIP(ruleType RuleType, cidr string) error {
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

func (s *YAMLStore) AddIPPortRule(rule IPPortRule) error {
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

func (s *YAMLStore) RemoveIPPortRule(cidr string, port uint16, protocol string) error {
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

func (s *YAMLStore) LoadAll() (whitelist []IPRule, lockList []IPRule, ipPortRules []IPPortRule, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Load from config
	configData, _ := s.readFile(s.configPath)
	whitelist = configData.Whitelist
	ipPortRules = configData.IPPortRules

	// Load from lock file
	lockData, _ := s.readFile(s.lockFilePath)
	lockList = lockData.LockList

	return
}

func (s *YAMLStore) readRawFile(path string) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	content, err := os.ReadFile(path)
	if err != nil {
		return data, err
	}
	err = yaml.Unmarshal(content, &data)
	return data, err
}

func (s *YAMLStore) readFile(path string) (fileData, error) {
	var data fileData
	content, err := os.ReadFile(path)
	if err != nil {
		return data, err
	}
	err = yaml.Unmarshal(content, &data)
	return data, err
}

func (s *YAMLStore) updateFile(path string, updater func(*fileData)) error {
	// Read raw to preserve other fields
	raw, _ := s.readRawFile(path)

	// Read typed to easily modify
	typed, _ := s.readFile(path)
	updater(&typed)

	// Sync typed back to raw
	raw["whitelist"] = typed.Whitelist
	raw["lock_list"] = typed.LockList
	raw["ip_port_rules"] = typed.IPPortRules

	content, err := yaml.Marshal(&raw)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}
