package main

import (
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Rules []Rule `yaml:"rules"`
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
