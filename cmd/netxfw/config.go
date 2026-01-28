package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Rules        []Rule                 `yaml:"rules"`
	Whitelist    []string               `yaml:"whitelist"`
	LockListFile string                 `yaml:"lock_list_file"`
	MetricsPort  int                    `yaml:"metrics_port"`
	Plugins      []string               `yaml:"plugins"`
	PluginConfig map[string]interface{} `yaml:",inline"`
}

type Rule struct {
	Name      string `yaml:"name"`
	Port      int    `yaml:"port"`
	Threshold int    `yaml:"threshold"`
	Duration  string `yaml:"duration"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}

func LoadPluginConfig(pluginName string) (interface{}, error) {
	// Try rules/plugins/<pluginName>.yaml or rules/plugins/<pluginName-without-plugins>.yaml
	// Example: netxfw-plugins-port -> netxfw-plugin-port.yaml
	configName := pluginName
	if strings.HasPrefix(pluginName, "netxfw-plugins-") {
		configName = "netxfw-plugin-" + strings.TrimPrefix(pluginName, "netxfw-plugins-")
	}

	path := fmt.Sprintf("rules/plugins/%s.yaml", configName)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Try the original plugin name as fallback
		path = fmt.Sprintf("rules/plugins/%s.yaml", pluginName)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Try /etc/netxfw/plugins/
			path = fmt.Sprintf("/etc/netxfw/plugins/%s.yaml", configName)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return nil, nil // No config file found
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config interface{}
	err = yaml.Unmarshal(data, &config)
	return config, err
}
