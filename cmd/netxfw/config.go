package main

import (
	"os"

	"github.com/livp123/netxfw/internal/plugins/types"
	"gopkg.in/yaml.v3"
)

func LoadGlobalConfig(path string) (*types.GlobalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg types.GlobalConfig
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}

func SaveGlobalConfig(path string, cfg *types.GlobalConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
