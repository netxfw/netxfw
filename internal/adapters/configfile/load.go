package configfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	domainconfig "github.com/netxfw/netxfw/internal/domain/config"
)

// Load reads a TOML config file into the canonical config model.
func Load(path string) (*domainconfig.Config, error) {
	safePath := filepath.Clean(path)
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, err
	}

	cfg := domainconfig.DefaultConfig()
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	if err := domainconfig.Validate(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// Encode serializes cfg to TOML.
func Encode(cfg *domainconfig.Config) ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
