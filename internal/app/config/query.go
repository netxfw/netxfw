package config

import (
	"fmt"

	cfgstore "github.com/netxfw/netxfw/internal/config"
	runtimestate "github.com/netxfw/netxfw/internal/domain/runtime"
	systemstate "github.com/netxfw/netxfw/internal/domain/system"
	"github.com/netxfw/netxfw/pkg/sdk"
)

type StatusSnapshot struct {
	Config  *sdk.GlobalConfig
	Desired systemstate.DesiredState
	Actual  runtimestate.ActualState
	Drift   runtimestate.StateDiff
}

func GetDefaultConfigPath() string {
	return cfgstore.GetDefaultConfigPath()
}

func SetConfigPath(path string) {
	cfgstore.SetConfigPath(path)
}

func GetConfigPath() string {
	return cfgstore.GetConfigPath()
}

func LoadConfig() (*sdk.GlobalConfig, error) {
	cfg, err := cfgstore.ReloadCurrentConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	return cfg, nil
}

func MutateLoadedConfig(fn func(*sdk.GlobalConfig) error) error {
	return cfgstore.MutateLoadedConfig(fn)
}

func GetBackupKeep() int {
	return cfgstore.GetBackupKeep()
}

func LoadStatusSnapshot(mgr sdk.ManagerInterface) (StatusSnapshot, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return StatusSnapshot{}, err
	}

	desired := systemstate.FromConfig(cfg)
	actual := runtimestate.FromManager(mgr)

	return StatusSnapshot{
		Config:  cfg,
		Desired: desired,
		Actual:  actual,
		Drift:   runtimestate.CompareDesired(desired, actual),
	}, nil
}

func GetConntrackMax() int {
	cfg, err := LoadConfig()
	if err == nil && cfg != nil && cfg.Capacity.Conntrack > 0 {
		return cfg.Capacity.Conntrack
	}
	return 100000
}
